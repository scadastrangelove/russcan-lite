//! Teddy-рантайм (base 128-бит, 8 бакетов) — `teddy.cpp`
//! `fdr_exec_teddy_128_templ` @ a1c107e. SIMD-порт: `prep_conf_teddy_128`
//! через `V128::pshufb` над 16-байтными блоками. Для блока val:
//! `r = OR_m (pshufb(maskLo[m], lo_nibbles) | pshufb(maskHi[m], hi_nibbles)) << m`;
//! по 0-битам r (после инверсии) — confirm по цепочке LitInfo (layout
//! идентичен FDR, `teddy_internal.h`: «first part compatible with an FDR»).
//! Блоки независимы (lookback на границе блока зануляется shl_bytes, как в C
//! palignr-zeroes → конфирм ловит cross-block литералы по реальному буферу).
//!
//! Компилятор выбирает Teddy для мелких наборов (≤128 коротких литералов —
//! перепись Д3). engineID 11–18 = base 8-бакет; 3–10 = fat 16-бакет (AVX2,
//! отдельный трек). Confirm-цепочка изолирована от FDR намеренно (не трогаем
//! зелёный fdr.rs); общий рефактор `Confirm` — потом.

use crate::{ExecResult, HwlmError, ScanCtl};
use russcan_simd::V128;

const NUM_BUCKETS: usize = 8;
const LIT_INFO_SIZE: usize = 32;
const FDR_LIT_FLAG_NOREPEAT: u8 = 1;
const ALL_GROUPS: u64 = !0;
const INVALID_MATCH_ID: u32 = !0;
/// `ROUNDUP_CL(sizeof(struct Teddy))` = ROUNDUP_CL(24) = 64 — оффсет maskBase.
const MASK_BASE_OFF: usize = 64;

#[inline(always)]
fn u32_le(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().unwrap()))
}
// Unchecked LE-чтения для hot-path confirm (тот же контракт, что в fdr.rs:
// CRC-целый байткод → валидные оффсеты). Убирают per-read bounds-check.
#[inline(always)]
unsafe fn u32_at(b: &[u8], off: usize) -> u32 {
    (b.as_ptr().add(off) as *const u32).read_unaligned()
}
#[inline(always)]
unsafe fn u64_at(b: &[u8], off: usize) -> u64 {
    (b.as_ptr().add(off) as *const u64).read_unaligned()
}

/// Валидирует confirm-регион (FDRConfirm/litIndex/LitInfo-цепочки) на вхождение
/// в `size` — раскладка идентична FDR (`fdr::validate_confirm`), Teddy делит те
/// же confirm-структуры. Один проход на load → confirm-hot-path unchecked-safe
/// при любой БД. Закрывает vuln-scan F-005.
fn validate_confirm(bytes: &[u8], conf_offset: usize, size: usize) -> Result<(), HwlmError> {
    let bad = || HwlmError::BadTable("teddy confirm-регион вне size");
    for idx in 0..NUM_BUCKETS {
        let cf = u32_le(bytes, conf_offset + idx * 4).ok_or_else(bad)? as usize;
        if cf == 0 {
            continue;
        }
        let fdrc = conf_offset.checked_add(cf).ok_or_else(bad)?;
        if fdrc + 32 > size {
            return Err(bad());
        }
        let n_bits = u32_le(bytes, fdrc + 16).ok_or_else(bad)?;
        if n_bits == 0 || n_bits >= 64 {
            continue;
        }
        let entries = 1u64 << n_bits;
        let tbl_end = entries
            .checked_mul(4)
            .and_then(|t| t.checked_add(fdrc as u64 + 32))
            .ok_or_else(bad)?;
        if tbl_end > size as u64 {
            return Err(bad());
        }
        for c in 0..entries as usize {
            let start = u32_le(bytes, fdrc + 32 + c * 4).ok_or_else(bad)? as usize;
            if start == 0 {
                continue;
            }
            let mut li = fdrc.checked_add(start).ok_or_else(bad)?;
            loop {
                if li + LIT_INFO_SIZE > size {
                    return Err(bad());
                }
                if bytes[li + 30] == 0 {
                    break;
                }
                li += LIT_INFO_SIZE;
            }
        }
    }
    Ok(())
}

/// Разобранная Teddy-таблица (заимствует байты движка).
pub struct TeddyTable<'a> {
    bytes: &'a [u8],
    // maskBase: 2*num_masks таблиц по 16 нибл-входов (u8 bucket-маска),
    // начиная с MASK_BASE_OFF; читаем через self.mask().
    num_masks: usize,
    conf_offset: usize,
}

impl<'a> TeddyTable<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, HwlmError> {
        let engine_id = u32_le(bytes, 0).ok_or(HwlmError::Truncated)?;
        // base 8-бакет: 11..=18. fat (3..=10) — вне скоупа (AVX2).
        if !(11..=18).contains(&engine_id) {
            return Err(HwlmError::BadTable("engineID вне base-teddy 11..18"));
        }
        let num_masks = ((engine_id - 11) / 2 + 1) as usize; // 1..4
        let size = u32_le(bytes, 4).ok_or(HwlmError::Truncated)? as usize;
        if size > bytes.len() {
            return Err(HwlmError::Truncated);
        }
        // Срез до `size`: confirm-читатели ниже unchecked (vuln-scan F-009).
        let bytes = &bytes[..size];
        let conf_offset = u32_le(bytes, 16).ok_or(HwlmError::Truncated)? as usize;
        // maskBase: 2*num_masks * 16 байт, начиная с MASK_BASE_OFF
        let mask_end = MASK_BASE_OFF + 2 * num_masks * 16;
        if mask_end > size
            || conf_offset + NUM_BUCKETS * 4 > size
            || conf_offset < mask_end
        {
            return Err(HwlmError::BadTable("оффсеты teddy не согласованы"));
        }
        // Валидируем confirm-регион один раз → hot-path unchecked-safe при любой
        // БД (vuln-scan F-005, зеркало FDR).
        validate_confirm(bytes, conf_offset, size)?;
        Ok(TeddyTable {
            bytes,
            num_masks,
            conf_offset,
        })
    }

    /// Порт `fdr_exec_teddy_128`. `cb(end, id)`, end = индекс последнего байта.
    pub fn exec(
        &self,
        buf: &[u8],
        start: usize,
        cb: &mut impl FnMut(u64, u32) -> ScanCtl,
    ) -> ExecResult {
        self.exec_squash(buf, start, &mut |end, id| (cb(end, id), 0))
    }

    /// Как `exec`, но колбэк возвращает `(ScanCtl, squash)` — squash-байт
    /// INCLUDED_JUMP для гашения бакета вложенного литерала в conf-слове.
    pub fn exec_squash(
        &self,
        buf: &[u8],
        start: usize,
        cb: &mut impl FnMut(u64, u32) -> (ScanCtl, u8),
    ) -> ExecResult {
        if start >= buf.len() {
            return ExecResult::Completed;
        }
        let mut ctx = TeddyCtx {
            table: self,
            buf,
            control: ALL_GROUPS,
            last_match: INVALID_MATCH_ID,
        };
        ctx.run(start, cb)
    }
}

struct TeddyCtx<'a, 'b> {
    table: &'b TeddyTable<'a>,
    buf: &'b [u8],
    control: u64,
    last_match: u32,
}

/// Порт `prep_conf_teddy_128_templ<NMSK>`: 16-байтный блок → m128, где байт b =
/// 8-битная маска бакетов-кандидатов для позиции b. `mask_base` — 2*num_masks
/// нибл-таблиц по 16 байт (V128); shl_bytes(m) = C palignr(res, zeroes, 16-m).
/// # Safety: `mask_base`+2*num_masks*16 в пределах таблицы (проверено в parse).
#[inline(always)]
unsafe fn prep_conf<V: V128>(masks: &[V; 8], num_masks: usize, mask0f: V, val: V) -> V {
    let lo = val.and(mask0f);
    let hi = val.shr64_by4().and(mask0f); // высокий нибл каждого байта
    let mut r = masks[0].pshufb(lo).or(masks[1].pshufb(hi));
    let mut m = 1;
    while m < num_masks {
        let res = masks[2 * m].pshufb(lo).or(masks[2 * m + 1].pshufb(hi));
        r = r.or(res.shl_bytes(m));
        m += 1;
    }
    r
}

impl TeddyCtx<'_, '_> {
    /// Диспатч SIMD-бэкенда (как в fdr.rs/accel): SSSE3 / NEON / скаляр.
    #[inline]
    fn run(&mut self, start: usize, cb: &mut impl FnMut(u64, u32) -> (ScanCtl, u8)) -> ExecResult {
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("ssse3") {
                return unsafe { self.run_simd::<russcan_simd::V128Sse>(start, cb) };
            }
            return unsafe { self.run_simd::<russcan_simd::V128Scalar>(start, cb) };
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                return unsafe { self.run_simd::<russcan_simd::V128Neon>(start, cb) };
            }
            return unsafe { self.run_simd::<russcan_simd::V128Scalar>(start, cb) };
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            unsafe { self.run_simd::<russcan_simd::V128Scalar>(start, cb) }
        }
    }

    /// SIMD-скан 16-байтными блоками. # Safety: `V` под проверенной feature.
    unsafe fn run_simd<V: V128>(
        &mut self,
        start: usize,
        cb: &mut impl FnMut(u64, u32) -> (ScanCtl, u8),
    ) -> ExecResult {
        let t = self.table;
        let buf = self.buf;
        let len = buf.len();
        let mask_base = t.bytes.as_ptr().add(MASK_BASE_OFF);
        let nm = t.num_masks;
        let mask0f = V::splat(0x0f);
        // maskBase-таблицы (2*nm ≤ 8 V128) грузим ОДИН раз — вне блочного цикла.
        let mut masks = [V::zeroes(); 8];
        for (j, m) in masks.iter_mut().enumerate().take(2 * nm) {
            *m = V::loadu(mask_base.add(j * 16));
        }

        // Two-phase (как FDR): горячий цикл собирает кандидат-блоки (r≠all-ones)
        // в ЛОКАЛЬНЫЙ стек-буфер (callback-free store не алиасит buf/масок → нет
        // пессимизации alias-анализа от confirm-callback), confirm — в flush.
        const CAP: usize = 64;
        let mut cbuf: [(usize, u64, u64); CAP] = [(0, 0, 0); CAP];
        let mut n = 0usize;

        use russcan_simd::MaskOps;
        let ones = V::ones();
        let mut p = start;
        while p + 16 <= len {
            let val = V::loadu(buf.as_ptr().add(p));
            let r = prep_conf::<V>(&masks, nm, mask0f, val);
            // Дешёвый SIMD-гейт «есть ли кандидат» (1 pcmpeqb+movemask), как C
            // diff128 — БЕЗ 2× vmovq XMM→GPR на каждый блок. Извлекаем lo/hi
            // только при наличии кандидата.
            if r.neq_mask(ones).any() {
                let lo = r.to_u64_low();
                let hi = r.shr_bytes(8).to_u64_low();
                cbuf[n] = (p, lo, hi);
                n += 1;
                if n == CAP {
                    if self.flush_candidates(&cbuf[..n], cb) {
                        return ExecResult::Terminated;
                    }
                    n = 0;
                }
            }
            p += 16;
        }
        // Хвост < 16 байт: копия в занулённый буфер + маскировка позиций ≥ tail.
        if p < len {
            let tail = len - p;
            let mut tmp = [0u8; 16];
            tmp[..tail].copy_from_slice(&buf[p..len]);
            let val = V::loadu(tmp.as_ptr());
            let mut rb = prep_conf::<V>(&masks, nm, mask0f, val).to_array();
            for b in rb.iter_mut().skip(tail) {
                *b = 0xff; // позиция вне буфера → инверсия даст 0, нет кандидата
            }
            let r = V::loadu(rb.as_ptr());
            let lo = r.to_u64_low();
            let hi = r.shr_bytes(8).to_u64_low();
            if lo != !0u64 || hi != !0u64 {
                cbuf[n] = (p, lo, hi);
                n += 1;
            }
        }
        if self.flush_candidates(&cbuf[..n], cb) {
            return ExecResult::Terminated;
        }
        ExecResult::Completed
    }

    /// Фаза 2: confirm собранных кандидат-блоков (split u64-половины как
    /// `confirm_teddy_64_128`), порядок сбора = порядок C. true = терминировано.
    #[inline]
    unsafe fn flush_candidates(
        &mut self,
        cands: &[(usize, u64, u64)],
        cb: &mut impl FnMut(u64, u32) -> (ScanCtl, u8),
    ) -> bool {
        for &(base, lo, hi) in cands {
            if lo != !0u64 && self.confirm_chunk(lo, base, 0, cb) == ScanCtl::Terminate {
                return true;
            }
            if hi != !0u64 && self.confirm_chunk(hi, base, 8, cb) == ScanCtl::Terminate {
                return true;
            }
        }
        false
    }

    /// Порт `do_confWithBit_teddy` для одной u64-половины: бит → (байт, бакет),
    /// позиция = base + bit/8 + offset. LSB-first = порядок C (позиция↑,бакет↑).
    #[inline(always)]
    unsafe fn confirm_chunk(
        &mut self,
        chunk: u64,
        base: usize,
        offset: usize,
        cb: &mut impl FnMut(u64, u32) -> (ScanCtl, u8),
    ) -> ScanCtl {
        let t = self.table;
        let buf = self.buf;
        let mut c = !chunk; // 0-бит chunk = кандидат
        while c != 0 {
            let bit = c.trailing_zeros() as usize;
            c &= c - 1;
            let byte = bit / NUM_BUCKETS + offset;
            let bucket = bit % NUM_BUCKETS;
            let cf = u32_at(t.bytes, t.conf_offset + bucket * 4);
            if cf == 0 {
                continue;
            }
            let fdrc = t.conf_offset + cf as usize;
            let pos = base + byte;
            let conf_val = conf_val(buf, pos);
            let (ctl, squash) = self.conf_with_bit(fdrc, pos, conf_val, cb);
            if squash != 0 {
                // INCLUDED_JUMP: гасим бакеты child в том же байт-группе chunk.
                c &= !((squash as u64) << (bit & !(NUM_BUCKETS - 1)));
            }
            if ctl == ScanCtl::Terminate {
                return ScanCtl::Terminate;
            }
        }
        ScanCtl::Continue
    }

    /// Порт `confWithBit` (Teddy использует ту же цепочку, что FDR).
    /// Возвращает Terminate, если колбэк попросил остановиться.
    fn conf_with_bit(
        &mut self,
        fdrc: usize,
        i: usize,
        conf_key: u64,
        cb: &mut impl FnMut(u64, u32) -> (ScanCtl, u8),
    ) -> (ScanCtl, u8) {
        let mut squash = 0u8;
        let b = self.table.bytes;
        let (andmsk, mult, n_bits) =
            unsafe { (u64_at(b, fdrc), u64_at(b, fdrc + 8), u32_at(b, fdrc + 16)) };
        if n_bits == 0 || n_bits >= 64 {
            return (ScanCtl::Continue, squash);
        }
        let c = ((conf_key & andmsk).wrapping_mul(mult)) >> (64 - n_bits);
        let start = unsafe { u32_at(b, fdrc + 32 + c as usize * 4) };
        if start == 0 {
            return (ScanCtl::Continue, squash);
        }
        let mut li = fdrc + start as usize;
        loop {
            // Ленивая загрузка (как fdr.rs): FP отваливаются на msk-проверке.
            let v = unsafe { u64_at(b, li) };
            let msk = unsafe { u64_at(b, li + 8) };
            let next = unsafe { *b.as_ptr().add(li + 30) };

            if conf_key & msk == v {
                'this_lit: {
                    let id = unsafe { u32_at(b, li + 24) };
                    let flags = unsafe { *b.as_ptr().add(li + 29) };
                    if self.last_match == id && flags & FDR_LIT_FLAG_NOREPEAT != 0 {
                        break 'this_lit;
                    }
                    let size = unsafe { *b.as_ptr().add(li + 28) };
                    if (size as usize) > i + 1 {
                        break 'this_lit;
                    }
                    let groups = unsafe { u64_at(b, li + 16) };
                    if groups & self.control == 0 {
                        break 'this_lit;
                    }
                    self.last_match = id;
                    let (ctl, sq) = cb(i as u64, id);
                    squash |= sq;
                    match ctl {
                        ScanCtl::Continue => self.control = ALL_GROUPS,
                        ScanCtl::Terminate => {
                            self.control = 0;
                            return (ScanCtl::Terminate, squash);
                        }
                    }
                }
            }
            if next == 0 {
                return (ScanCtl::Continue, squash);
            }
            li += LIT_INFO_SIZE;
        }
    }
}

/// confVal: 8 байт, оканчивающихся на p (data[p] = старший байт LE), с
/// нулевым заполнением до начала буфера (block mode, истории нет).
#[inline(always)]
fn conf_val(data: &[u8], p: usize) -> u64 {
    let mut v = 0u64;
    for j in 0..8 {
        // байт j (значимость 8j) = data[p-7+j]
        let idx = p as isize - 7 + j as isize;
        if idx >= 0 && (idx as usize) < data.len() {
            v |= (data[idx as usize] as u64) << (8 * j);
        }
    }
    v
}
