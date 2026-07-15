//! Генерик-алгоритмы accel-примитивов поверх [`V128`].
//!
//! Порт `nfa/shufti_simd.hpp`, `nfa/truffle_simd.hpp`, `nfa/vermicelli_simd.cpp`
//! и арх-блоков из `nfa/{x86,arm}/*.hpp` (vectorscan @ a1c107e). Структура
//! сканирования зеркалит C: невыровненный head-блок → выровненный цикл →
//! tail с перечитыванием (для стейтлесс-предикатов перекрытие безопасно).
//! Буферы короче 16 байт идут скалярным референсом (в C — slow-путь или
//! maskz-блок с ограничением по длине; результаты эквивалентны).
//!
//! Контракт unsafe: вызывающий гарантирует доступность ISA бэкенда `V`.

use super::reference;
use crate::{MaskOps, V128};

// --- Блоковые предикаты (порт blockSingleMask / blockDoubleMask) ---

/// Лейны, где байт принадлежит shufti-классу:
/// `mask_lo[b & 0xf] & mask_hi[b >> 4] != 0`.
#[inline(always)]
unsafe fn block_shufti<V: V128>(lo: V, hi: V, chars: V) -> V::Mask {
    let low4 = V::splat(0xf);
    let c_lo = chars.and(low4);
    let c_hi = chars.shr64_by4().and(low4);
    lo.pshufb(c_lo).and(hi.pshufb(c_hi)).nonzero_mask()
}

/// Лейны, где байт принадлежит truffle-классу: бит `(b >> 4) & 7` байта
/// `b & 0xf` маски highclear (b < 0x80) или highset (b >= 0x80).
#[inline(always)]
unsafe fn block_truffle<V: V128>(clear: V, set: V, chars: V) -> V::Mask {
    let highconst = V::splat(0x80);
    let shuf_mask_hi = V::splat_u64(0x8040201008040201);
    // pshufb зануляет лейны с битом 7 => shuf1 живёт только для b < 0x80
    let shuf1 = clear.pshufb(chars);
    // b ^ 0x80: для b >= 0x80 бит 7 снят => shuf2 живёт только для b >= 0x80
    let shuf2 = set.pshufb(chars.xor(highconst));
    // (b >> 4) с перетеканием из соседнего байта: биты 4..6 pshufb игнорирует,
    // бит 7 снимаем and_not'ом — остаётся индекс (b >> 4) & 0xf
    let t2 = chars.shr64_by4().and_not(highconst);
    let shuf3 = shuf_mask_hi.pshufb(t2);
    shuf1.or(shuf2).and(shuf3).nonzero_mask()
}

/// Двойной shufti: маски ИНВЕРТИРОВАНЫ (снятый бит = совпадение бакета).
/// Возвращает лейны j, где пара (j-1, j) матчится; лейн 0 использует
/// последний байт `*state` предыдущего блока (alignr на 15).
#[inline(always)]
unsafe fn block_shufti_double<V: V128>(
    m1_lo: V,
    m1_hi: V,
    m2_lo: V,
    m2_hi: V,
    state: &mut V,
    chars: V,
) -> V::Mask {
    let low4 = V::splat(0xf);
    let chars_lo = chars.and(low4);
    let chars_hi = chars.shr64_by4().and(low4);
    let c1 = m1_lo.pshufb(chars_lo).or(m1_hi.pshufb(chars_hi));
    let c2 = m2_lo.pshufb(chars_lo).or(m2_hi.pshufb(chars_hi));
    let c = c1.alignr_15(*state).or(c2);
    *state = c1;
    // совпадение там, где какой-то бит остался нулевым
    c.neq_mask(V::ones())
}

// --- Скан-скелеты (порт shuftiExecReal и родни) ---

/// Вперёд: первый лейн-матч стейтлесс-предиката. Требует `buf.len() >= 16`.
#[inline(always)]
unsafe fn scan_fwd<V: V128>(buf: &[u8], mut block: impl FnMut(V) -> V::Mask) -> Option<usize> {
    debug_assert!(buf.len() >= 16);
    let start = buf.as_ptr();
    let len = buf.len();
    let mut d = 0usize;

    let align_off = start.align_offset(16);
    if align_off != 0 {
        let m = block(V::loadu(start));
        if let Some(i) = m.first() {
            return Some(i as usize);
        }
        d = align_off;
    }

    while d + 16 <= len {
        let m = block(V::loadu(start.add(d)));
        if let Some(i) = m.first() {
            return Some(d + i as usize);
        }
        d += 16;
    }

    if d != len {
        // Хвост перечитывает до 15 уже проверенных байт — они заведомо
        // без матча, поэтому первый матч блока корректен.
        let tail = len - 16;
        let m = block(V::loadu(start.add(tail)));
        if let Some(i) = m.first() {
            return Some(tail + i as usize);
        }
    }
    None
}

/// Назад: последний лейн-матч стейтлесс-предиката. Требует `buf.len() >= 16`.
#[inline(always)]
unsafe fn scan_rev<V: V128>(buf: &[u8], mut block: impl FnMut(V) -> V::Mask) -> Option<usize> {
    debug_assert!(buf.len() >= 16);
    let start = buf.as_ptr();
    let len = buf.len();
    let mut d = len;

    let end_align = (start.add(len) as usize) & 15;
    if end_align != 0 {
        let m = block(V::loadu(start.add(len - 16)));
        if let Some(i) = m.last() {
            return Some(len - 16 + i as usize);
        }
        d = len - end_align;
    }

    while d >= 16 {
        d -= 16;
        let m = block(V::loadu(start.add(d)));
        if let Some(i) = m.last() {
            return Some(d + i as usize);
        }
    }

    if d != 0 {
        // Голова: лейны >= d уже проверены и без матча.
        let m = block(V::loadu(start));
        if let Some(i) = m.last() {
            debug_assert!((i as usize) < d);
            return Some(i as usize);
        }
    }
    None
}

// --- Публичные генерики ---

pub unsafe fn shufti_exec<V: V128>(
    mask_lo: &[u8; 16],
    mask_hi: &[u8; 16],
    buf: &[u8],
) -> Option<usize> {
    if buf.len() < 16 {
        return reference::shufti_fwd(mask_lo, mask_hi, buf);
    }
    let lo = V::loadu(mask_lo.as_ptr());
    let hi = V::loadu(mask_hi.as_ptr());
    scan_fwd::<V>(buf, |chars| unsafe { block_shufti(lo, hi, chars) })
}

pub unsafe fn rshufti_exec<V: V128>(
    mask_lo: &[u8; 16],
    mask_hi: &[u8; 16],
    buf: &[u8],
) -> Option<usize> {
    if buf.len() < 16 {
        return reference::shufti_rev(mask_lo, mask_hi, buf);
    }
    let lo = V::loadu(mask_lo.as_ptr());
    let hi = V::loadu(mask_hi.as_ptr());
    scan_rev::<V>(buf, |chars| unsafe { block_shufti(lo, hi, chars) })
}

pub unsafe fn truffle_exec<V: V128>(
    mask_highclear: &[u8; 16],
    mask_highset: &[u8; 16],
    buf: &[u8],
) -> Option<usize> {
    if buf.len() < 16 {
        return reference::truffle_fwd(mask_highclear, mask_highset, buf);
    }
    let clear = V::loadu(mask_highclear.as_ptr());
    let set = V::loadu(mask_highset.as_ptr());
    scan_fwd::<V>(buf, |chars| unsafe { block_truffle(clear, set, chars) })
}

pub unsafe fn rtruffle_exec<V: V128>(
    mask_highclear: &[u8; 16],
    mask_highset: &[u8; 16],
    buf: &[u8],
) -> Option<usize> {
    if buf.len() < 16 {
        return reference::truffle_rev(mask_highclear, mask_highset, buf);
    }
    let clear = V::loadu(mask_highclear.as_ptr());
    let set = V::loadu(mask_highset.as_ptr());
    scan_rev::<V>(buf, |chars| unsafe { block_truffle(clear, set, chars) })
}

/// CASE_CLEAR апстрима: маска 0xdf снимает бит 0x20 (ASCII-регистр).
#[inline(always)]
fn case_mask(nocase: bool) -> u8 {
    if nocase {
        0xdf
    } else {
        0xff
    }
}

pub unsafe fn vermicelli_exec<V: V128>(c: u8, nocase: bool, buf: &[u8]) -> Option<usize> {
    if buf.len() < 16 {
        return reference::verm_fwd(c, nocase, buf);
    }
    let cm = case_mask(nocase);
    let chars = V::splat(c & cm);
    let casemask = V::splat(cm);
    scan_fwd::<V>(buf, |data| unsafe { data.and(casemask).eq_mask(chars) })
}

pub unsafe fn nvermicelli_exec<V: V128>(c: u8, nocase: bool, buf: &[u8]) -> Option<usize> {
    if buf.len() < 16 {
        return reference::nverm_fwd(c, nocase, buf);
    }
    let cm = case_mask(nocase);
    let chars = V::splat(c & cm);
    let casemask = V::splat(cm);
    scan_fwd::<V>(buf, |data| unsafe { data.and(casemask).neq_mask(chars) })
}

pub unsafe fn rvermicelli_exec<V: V128>(c: u8, nocase: bool, buf: &[u8]) -> Option<usize> {
    if buf.len() < 16 {
        return reference::verm_rev(c, nocase, buf);
    }
    let cm = case_mask(nocase);
    let chars = V::splat(c & cm);
    let casemask = V::splat(cm);
    scan_rev::<V>(buf, |data| unsafe { data.and(casemask).eq_mask(chars) })
}

pub unsafe fn rnvermicelli_exec<V: V128>(c: u8, nocase: bool, buf: &[u8]) -> Option<usize> {
    if buf.len() < 16 {
        return reference::nverm_rev(c, nocase, buf);
    }
    let cm = case_mask(nocase);
    let chars = V::splat(c & cm);
    let casemask = V::splat(cm);
    scan_rev::<V>(buf, |data| unsafe { data.and(casemask).neq_mask(chars) })
}

/// Двойной shufti — порт `shuftiDoubleExecReal` (включая фикс #402:
/// `check_last_byte` даёт resume-точку на последнем байте).
///
/// Семантика возврата — как у C: `Some(p)` — позиция, где вызывающему нужно
/// остановиться/продолжить (первый символ пары ЛИБО resume-точка `len-1`);
/// `None` — просканировано до конца.
pub unsafe fn shufti_double_exec<V: V128>(
    m1_lo: &[u8; 16],
    m1_hi: &[u8; 16],
    m2_lo: &[u8; 16],
    m2_hi: &[u8; 16],
    buf: &[u8],
) -> Option<usize> {
    if buf.is_empty() {
        return None;
    }
    let m1l = V::loadu(m1_lo.as_ptr());
    let m1h = V::loadu(m1_hi.as_ptr());
    let m2l = V::loadu(m2_lo.as_ptr());
    let m2h = V::loadu(m2_hi.as_ptr());

    let start = buf.as_ptr();
    let len = buf.len();
    // first_char_mask: c1-маска предыдущего блока (для пар через границу)
    let mut state = V::ones();
    let mut d = 0usize;

    if len >= 16 {
        let align_off = start.align_offset(16);
        if align_off != 0 {
            let chars = V::loadu(start);
            let m = block_shufti_double(m1l, m1h, m2l, m2h, &mut state, chars);
            if let Some(i) = m.first() {
                // При свежем state лейн 0 не матчится => i >= 1.
                debug_assert!(i >= 1);
                return Some(i as usize - 1);
            }
            d = align_off;
            // Сдвигаем state так, чтобы его байт 15 стал байтом (d-1) буфера.
            state = state.shl_bytes(16 - align_off);
        }

        while d + 16 <= len {
            let chars = V::loadu(start.add(d));
            let m = block_shufti_double(m1l, m1h, m2l, m2h, &mut state, chars);
            if let Some(i) = m.first() {
                let pos = d + i as usize - 1;
                // C: матчи на len-1 откладываются до check_last_byte
                if pos < len - 1 {
                    return Some(pos);
                }
            }
            d += 16;
        }
    }

    let mask_len = len.min(16);
    if d != len {
        let (chars, tail_base) = if len < 16 {
            // Короткий буфер: zero-pad, паразитные матчи в паддинге
            // отфильтрует pos < len-1.
            (V::load_partial(buf), 0usize)
        } else {
            // Перечитывание хвоста заново покрывает контекст пары через
            // границу блока, поэтому state сбрасывается.
            (V::loadu(start.add(len - 16)), len - 16)
        };
        state = V::ones();
        let m = block_shufti_double(m1l, m1h, m2l, m2h, &mut state, chars);
        if let Some(i) = m.first() {
            debug_assert!(i >= 1);
            if i >= 1 {
                let pos = tail_base + i as usize - 1;
                if pos < len - 1 {
                    return Some(pos);
                }
            }
        }
    }

    check_last_byte::<V>(m2l, m2h, state, mask_len, len)
}

/// Порт `check_last_byte` (#402): последний байт — валидная остановка, если
/// он может быть первым символом пары, чей второй символ в следующем чанке.
#[inline(always)]
unsafe fn check_last_byte<V: V128>(
    m2_lo: V,
    m2_hi: V,
    state: V,
    mask_len: usize,
    len: usize,
) -> Option<usize> {
    debug_assert!(mask_len >= 1);
    let last_elem = state.to_array()[mask_len - 1];

    let mut reduce = m2_lo.or(m2_hi);
    let mut i = 16usize;
    while i >= 2 {
        reduce = reduce.or(reduce.shr_bytes(i / 2));
        i /= 2;
    }
    let match_inverted = reduce.to_array()[0] | last_elem;

    if match_inverted != 0xff || last_elem != 0xff {
        Some(len - 1)
    } else {
        None
    }
}
