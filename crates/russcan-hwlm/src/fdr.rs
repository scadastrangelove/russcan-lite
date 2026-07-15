//! FDR: SIMD-мульти-литеральный матчер — порт `fdr/fdr.c` @ a1c107e
//! (engineID 0; Teddy-варианты — отдельный модуль).
//!
//! Алгоритм: скользящее 128-битное состояние исключающих битов. Для каждой
//! позиции блока (16 байт) по domain-хэшу окна берётся u64-запись hash-таблицы
//! `ft` (бит=1 «бакет b не может кончиться через j байт»), записи сдвигаются
//! по позиции и OR-ятся в состояние; инверсия младших u64 даёт кандидатов
//! (байт, бакет) → confirm по цепочке LitInfo (`fdr_confirm_runtime.h`).
//! Края буфера обрабатываются зонами с копированием (`createShortZone` и
//! родня), затопления — flood-путём (`flood_runtime.h`).
//!
//! Состояние — настоящий m128-регистр через `russcan_simd::V128` (SSE/NEON,
//! скаляр-fallback); table-lookup грузятся память→XMM (`load_low64`) без
//! round-trip через GPR. Диспатч бэкенда — в `run` (feature-detect как в accel).
//!
//! Таблица — недоверенные байты: статика валидируется в `parse`, динамические
//! оффсеты (confirm-цепочки, flood-структуры) читаются через checked-доступ
//! и при выходе за границы тихо завершают скан (fuzz-инвариант: без паник).

use crate::{ExecResult, HwlmError, ScanCtl};
use russcan_simd::V128;

/// `zone_or_mask[shift]`: `shift` младших байт = 0xff, остальные 0.
/// # Safety: делегирует `V::loadu` на валидные 16 байт стека.
#[inline(always)]
unsafe fn zone_or_mask<V: V128>(shift: usize) -> V {
    let mut m = [0u8; 16];
    for b in m.iter_mut().take(shift) {
        *b = 0xff;
    }
    V::loadu(m.as_ptr())
}

const ITER_BYTES: usize = 16;
const FT_OFFSET: usize = 64; // ROUNDUP_CL(sizeof(struct FDR) = 48)
const NUM_CONF_BUCKETS: usize = 8;
const INVALID_MATCH_ID: u32 = !0u32;
const ALL_GROUPS: u64 = !0u64;

const FLOOD_MINIMUM_SIZE: usize = 256;
const FLOOD_BACKOFF_START: u32 = 32;
const FDR_FLOOD_MAX_IDS: u16 = 16;
const FLOOD_STRUCT_SIZE: usize = 208; // sizeof(FDRFlood), contract/
const LIT_INFO_SIZE: usize = 32; // sizeof(LitInfo), contract/
const FDR_LIT_FLAG_NOREPEAT: u8 = 1;

#[inline(always)]
fn u16_le(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().unwrap()))
}
#[inline(always)]
fn u32_le(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().unwrap()))
}
#[inline(always)]
fn u64_le(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().unwrap()))
}

// Unchecked LE-чтения для hot-path (scan + confirm). Границы гарантированы:
// (1) байткод прошёл CRC в `SerializedDb::parse` → внутренние оффсеты валидны;
// (2) данные читаются в пределах зонных инвариантов (см. вызовы).
// Убирают per-read bounds-check — 2× инструкций на confirm по профилю.
#[inline(always)]
unsafe fn u32_at(b: &[u8], off: usize) -> u32 {
    (b.as_ptr().add(off) as *const u32).read_unaligned()
}
#[inline(always)]
unsafe fn u64_at(b: &[u8], off: usize) -> u64 {
    (b.as_ptr().add(off) as *const u64).read_unaligned()
}

/// Валидирует confirm-регион (`bytes` уже срезан до `size`): каждый достижимый
/// `FDRConfirm` (по бакетным `cf`), его litIndex-таблица (`2^n_bits` u32) и
/// каждая LitInfo-цепочка целиком лежат в `[0, size)`. Один проход на load →
/// `do_confirm`/`conf_with_bit` читают эти оффсеты unchecked, но memory-safe
/// при любой (в т.ч. враждебной CRC-валидной) БД. Цепочка `li += 32` строго
/// растёт и ограничена `size` → конечна (нет обхода-в-цикле).
/// Оффсеты FDRConfirm: andmsk@0, mult@8, n_bits@16, groups@24 (заголовок 32 Б),
/// далее litIndex; LitInfo: v@0, msk@8, groups@16, id@24, size@28, flags@29,
/// next@30 (шаг `LIT_INFO_SIZE`). Порядок совпадает с чтениями hot-path.
fn validate_confirm(bytes: &[u8], conf_offset: usize, size: usize) -> Result<(), HwlmError> {
    let bad = || HwlmError::BadTable("confirm-регион вне size");
    for idx in 0..NUM_CONF_BUCKETS {
        let cf = u32_le(bytes, conf_offset + idx * 4).ok_or_else(bad)? as usize;
        if cf == 0 {
            continue;
        }
        let fdrc = conf_offset.checked_add(cf).ok_or_else(bad)?;
        // Заголовок FDRConfirm: read'ы до fdrc+24..32 (groups u64) → нужен +32.
        if fdrc + 32 > size {
            return Err(bad());
        }
        let n_bits = u32_le(bytes, fdrc + 16).ok_or_else(bad)?;
        if n_bits == 0 || n_bits >= 64 {
            continue; // hot-path тут делает `return squash` — litIndex не читается
        }
        // litIndex: 2^n_bits записей u32 сразу за 32-байтным заголовком.
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
                    break; // терминатор цепочки (next==0)
                }
                li += LIT_INFO_SIZE;
            }
        }
    }
    Ok(())
}

/// Распарсенная FDR-таблица (заимствует байты движка из байткода/шима).
pub struct FdrTable<'a> {
    bytes: &'a [u8],
    stride: usize,
    domain_mask: u64,
    start_state: u128,
    conf_offset: usize,
    flood_offset: usize,
}

impl<'a> FdrTable<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, HwlmError> {
        if bytes.len() < FT_OFFSET {
            return Err(HwlmError::Truncated);
        }
        let engine_id = u32_le(bytes, 0).unwrap();
        if engine_id != 0 {
            return Err(HwlmError::BadTable("engineID != 0 (teddy?)"));
        }
        let size = u32_le(bytes, 4).unwrap() as usize;
        if size > bytes.len() {
            return Err(HwlmError::Truncated);
        }
        // Срез ровно до `size`: confirm-читатели ниже unchecked → ограничиваем
        // их окно таблицей, а не всем блобом-до-EOF (vuln-scan F-009: иначе
        // враждебная таблица читала бы соседний регион в пределах buffer.len()).
        let bytes = &bytes[..size];
        let conf_offset = u32_le(bytes, 16).unwrap() as usize;
        let flood_offset = u32_le(bytes, 20).unwrap() as usize;
        let stride = bytes[24] as usize;
        let domain = bytes[25];
        let domain_mask = u16_le(bytes, 26).unwrap() as u64;
        let start_state = u128::from_le_bytes(bytes[32..48].try_into().unwrap());

        if !matches!(stride, 1 | 2 | 4) {
            return Err(HwlmError::BadTable("stride не 1/2/4"));
        }
        // fdr.c: assert(fdr->domain > 8 && fdr->domain < 16)
        if !(9..16).contains(&domain) || domain_mask != (1u64 << domain) - 1 {
            return Err(HwlmError::BadTable("domain/domainMask"));
        }
        // hash-таблица ft: (domainMask+1) записей u64 начиная с 64
        let ft_end = FT_OFFSET + ((domain_mask as usize) + 1) * 8;
        // confBase: 8 бакетных u32; flood: индекс u32[256] + хотя бы 1 FDRFlood
        if ft_end > conf_offset
            || conf_offset + NUM_CONF_BUCKETS * 4 > flood_offset
            || flood_offset + 256 * 4 + FLOOD_STRUCT_SIZE > size
        {
            return Err(HwlmError::BadTable("оффсеты таблиц не согласованы"));
        }
        // Валидируем confirm-регион (FDRConfirm/litIndex/LitInfo-цепочки) на
        // вхождение в `size` ОДИН раз здесь → hot-path do_confirm/conf_with_bit
        // читает оффсеты из байткода unchecked, оставаясь memory-safe при любой
        // (в т.ч. враждебной CRC-валидной) БД. Off-scan → 0 стоимости на
        // throughput. Закрывает vuln-scan F-001/002/004/005.
        validate_confirm(bytes, conf_offset, size)?;
        Ok(FdrTable {
            bytes,
            stride,
            domain_mask,
            start_state,
            conf_offset,
            flood_offset,
        })
    }

    /// Порт `fdrExec` (block mode). `cb(end, id)`, end — индекс последнего
    /// байта матча в `buf`. Простой колбэк без squash (для тестов/noodle-паритета).
    pub fn exec(
        &self,
        buf: &[u8],
        start: usize,
        cb: &mut impl FnMut(u64, u32) -> ScanCtl,
    ) -> ExecResult {
        self.exec_squash(buf, start, &mut |end, id| (cb(end, id), 0))
    }

    /// Как `exec`, но колбэк возвращает `(ScanCtl, squash)` — squash-байт
    /// INCLUDED_JUMP для гашения бакета вложенного литерала в conf-слове
    /// (иначе child подтверждается второй раз → дубликаты).
    pub fn exec_squash(
        &self,
        buf: &[u8],
        start: usize,
        cb: &mut impl FnMut(u64, u32) -> (ScanCtl, u8),
    ) -> ExecResult {
        if start >= buf.len() {
            return ExecResult::Completed;
        }
        let mut ctx = ExecCtx {
            table: self,
            buf,
            control: ALL_GROUPS,
            last_match: INVALID_MATCH_ID,
            flood_backoff: FLOOD_BACKOFF_START,
            first_flood_detect: next_flood_detect(buf, FLOOD_BACKOFF_START),
        };
        ctx.run(start, cb)
    }
}

/// Зона сканирования: либо окно основного буфера, либо скопированный край.
/// `Copy` + инлайновый `copied` (не `Box`): зоны живут в стековом `[Zone; 3]`,
/// без heap-аллокаций на скан (порт `struct zone zones[ZONE_TOTAL]`). Раньше
/// `Vec<Zone>` + `Box<[u8;64]>` давали 2–3 malloc/скан — доминировали на
/// маленьких буферах (64B: +51ns фикс-оверхед vs Vectorscan).
#[derive(Clone, Copy)]
struct Zone {
    /// Локальный буфер для краевых зон (ZONE_TOTAL_SIZE); `is_copied` — валиден ли.
    copied: [u8; 64],
    is_copied: bool,
    start: usize,
    end: usize,
    shift: usize,
    /// main_pos = zone_pos + adjust (порт zone_pointer_adjust).
    adjust: isize,
    /// Индекс «пробовать flood с этой позиции» в системе координат зоны.
    flood_from: usize,
}

impl Zone {
    const EMPTY: Zone = Zone {
        copied: [0u8; 64],
        is_copied: false,
        start: 0,
        end: 0,
        shift: 0,
        adjust: 0,
        flood_from: 0,
    };
    #[inline]
    fn data<'b>(&'b self, buf: &'b [u8]) -> &'b [u8] {
        if self.is_copied {
            &self.copied[..]
        } else {
            buf
        }
    }
}

/// Порт `createShortZone`: весь скан (<= 16 байт данных) в одном зонном буфере.
fn create_short_zone(buf: &[u8], begin: usize, end: usize) -> Zone {
    let mut zb = [0u8; 64];
    let z_len = end - begin;
    debug_assert!(z_len > 0 && z_len <= ITER_BYTES);
    let shift = ITER_BYTES - z_len;

    // [0..16): последние 16 байт истории; block mode — нули (fake_history)
    const DATA_OFF: usize = 16;
    // copy_len байт буфера, оканчивающихся на end (включая до 8 байт до begin
    // для конф-хэшей)
    let copy_len = end.min(ITER_BYTES + 8);
    zb[DATA_OFF..DATA_OFF + copy_len].copy_from_slice(&buf[end - copy_len..end]);

    let z_end = DATA_OFF + copy_len;
    // паддинг-байт (для domain > 8 overhang)
    zb[z_end] = 0;
    Zone {
        start: z_end - ITER_BYTES,
        end: z_end,
        shift,
        adjust: end as isize - z_end as isize,
        flood_from: 64, // конец зонного буфера: flood в краевых зонах не пробуем
        copied: zb,
        is_copied: true,
    }
}

/// Порт `createStartZone`: первые ITER_BYTES при len > ITER_BYTES.
fn create_start_zone(buf: &[u8], begin: usize) -> Zone {
    let mut zb = [0u8; 64];
    const DATA_OFF: usize = 8; // sizeof(CONF_TYPE) байт истории (нули)
    let end = begin + ITER_BYTES;
    let copy_len = end.min(ITER_BYTES + 8);
    zb[DATA_OFF..DATA_OFF + copy_len].copy_from_slice(&buf[end - copy_len..end]);
    let z_end = DATA_OFF + copy_len;
    // start-зона требует данных после себя: паддинг = реальный следующий байт
    zb[z_end] = buf[end];
    Zone {
        start: z_end - ITER_BYTES,
        end: z_end,
        shift: 0,
        adjust: end as isize - z_end as isize,
        flood_from: 64,
        copied: zb,
        is_copied: true,
    }
}

/// Порт `createEndZone`: хвост (и, если main-зоне не хватило 3 байт запаса,
/// дополнительный полный ITER_BYTES).
fn create_end_zone(buf: &[u8], begin: usize, end: usize) -> Zone {
    let mut zb = [0u8; 64];
    let z_len = end - begin;
    debug_assert!(z_len > 0);
    let (z_len_first, iter_bytes_second) = if z_len > ITER_BYTES {
        (z_len - ITER_BYTES, ITER_BYTES)
    } else {
        (z_len, 0)
    };
    let shift = ITER_BYTES - z_len_first;

    let end_first = end - iter_bytes_second;
    let copy_len_first = end_first.min(ITER_BYTES + 8);
    let total_copy_len = copy_len_first + iter_bytes_second;

    zb[..copy_len_first].copy_from_slice(&buf[end_first - copy_len_first..end_first]);
    if iter_bytes_second > 0 {
        zb[copy_len_first..total_copy_len].copy_from_slice(&buf[end - ITER_BYTES..end]);
    }
    zb[total_copy_len] = 0;

    let z_end = total_copy_len;
    Zone {
        start: z_end - ITER_BYTES - iter_bytes_second,
        end: z_end,
        shift,
        adjust: end as isize - z_end as isize,
        flood_from: 64,
        copied: zb,
        is_copied: true,
    }
}

/// Порт `prepareZones`. Пишет зоны в стековый `out` (макс. 3: start/main/end
/// или 1 short), возвращает их число — без heap (порт `zones[ZONE_TOTAL]`).
fn prepare_zones(
    buf: &[u8],
    start: usize,
    first_flood_detect: usize,
    out: &mut [Zone; 3],
) -> usize {
    let len = buf.len();
    let remaining = len - start;
    if remaining <= ITER_BYTES {
        out[0] = create_short_zone(buf, start, len);
        return 1;
    }
    let mut n = 0;
    out[n] = create_start_zone(buf, start);
    n += 1;
    let mut ptr = start + ITER_BYTES;

    // main-зона: кратно ITER_BYTES и без последних 3 байт (чтение вперёд)
    let main_end = start + (len - start - 3) / ITER_BYTES * ITER_BYTES;
    if main_end > ptr {
        out[n] = Zone {
            copied: [0u8; 64],
            is_copied: false,
            start: ptr,
            end: main_end,
            shift: 0,
            adjust: 0,
            flood_from: first_flood_detect,
        };
        n += 1;
        ptr = main_end;
    }
    out[n] = create_end_zone(buf, ptr, len);
    n + 1
}

/// Порт `nextFloodDetect` (64-битная ветка): дешёвая проба «есть ли флуд».
/// Адресное выравнивание C-версии воспроизводится от фактического указателя.
fn next_flood_detect(buf: &[u8], flood_backoff: u32) -> usize {
    let len = buf.len();
    if len < FLOOD_MINIMUM_SIZE {
        return len;
    }
    let addr = buf.as_ptr() as usize;
    let rup = |i: usize| ((addr + i + 7) & !7) - addr;
    let ld = |i: usize| u64_le(buf, i).unwrap_or(0);

    if ld(rup(0)) == ld(rup(8)) {
        return flood_backoff as usize;
    }
    if ld(rup(len / 2)) == ld(rup(len / 2 + 8)) {
        return flood_backoff as usize;
    }
    if ld(rup(len - 24)) == ld(rup(len - 16)) {
        return flood_backoff as usize;
    }
    len
}

struct ExecCtx<'t, 'a> {
    table: &'t FdrTable<'a>,
    buf: &'t [u8],
    control: u64,
    last_match: u32,
    flood_backoff: u32,
    first_flood_detect: usize,
}

/// Порт `get_conf_stride` на `V128`-регистре (x86/fdr_impl.h). Свободная
/// функция: инварианты (ft-база, domain_mask, stride) — параметры, чтобы LLVM
/// не перезагружал поля self.table каждую итерацию hot-loop.
/// # Safety: `V` под проверенной feature; `ft`+reach*8 в пределах таблицы
/// (reach ≤ domain_mask, размер проверен в parse); зонный инвариант для data.
#[inline(always)]
unsafe fn get_conf_stride<V: V128>(
    ft: *const u8,
    dm: u64,
    stride: usize,
    data: &[u8],
    it: usize,
    s: &mut V,
) -> (u64, u64) {
    // load_low64 напрямую (без closure): ft + reach*8, reach ≤ domain_mask.
    #[inline(always)]
    unsafe fn ld<V: V128>(ft: *const u8, reach: u64) -> V {
        V::load_low64(ft.add(reach as usize * 8))
    }
    // Зонный инвариант: it+16 ≤ z.end ≤ len−3 (main) / внутри 64-байт края.
    let it_hi = u64_at(data, it);
    let it_lo = u64_at(data, it + 8);

    let reach0 = dm & it_hi;
    let reach4 = dm & (it_hi >> 32);
    let reach8 = dm & it_lo;
    let reach12 = dm & (it_lo >> 32);

    let st0 = ld::<V>(ft, reach0);
    let st4 = ld::<V>(ft, reach4).shl_bytes(4);
    let st8 = ld::<V>(ft, reach8);
    let st12 = ld::<V>(ft, reach12).shl_bytes(4);

    *s = s.or(st0).or(st4);

    if stride == 4 {
        let conf0 = s.to_u64_low() ^ !0u64;
        *s = s.shr_bytes(8).or(st8).or(st12);
        let conf8 = s.to_u64_low() ^ !0u64;
        *s = s.shr_bytes(8);
        return (conf0, conf8);
    }

    let reach2 = dm & (it_hi >> 16);
    let reach6 = dm & (it_hi >> 48);
    let reach10 = dm & (it_lo >> 16);
    let reach14 = dm & (it_lo >> 48);

    let st2 = ld::<V>(ft, reach2).shl_bytes(2);
    let st6 = ld::<V>(ft, reach6).shl_bytes(6);
    let st10 = ld::<V>(ft, reach10).shl_bytes(2);
    let st14 = ld::<V>(ft, reach14).shl_bytes(6);

    *s = s.or(st2).or(st6);

    if stride == 2 {
        let conf0 = s.to_u64_low() ^ !0u64;
        *s = s.shr_bytes(8).or(st8).or(st10).or(st12).or(st14);
        let conf8 = s.to_u64_low() ^ !0u64;
        *s = s.shr_bytes(8);
        return (conf0, conf8);
    }

    // stride == 1
    let reach1 = dm & (it_hi >> 8);
    let reach3 = dm & (it_hi >> 24);
    let reach5 = dm & (it_hi >> 40);
    let reach7 = dm & ((it_hi >> 56) | (it_lo << 8));
    let reach9 = dm & (it_lo >> 8);
    let reach11 = dm & (it_lo >> 24);
    let reach13 = dm & (it_lo >> 40);
    let reach15 = dm & u32_at(data, it + 15) as u64;

    let st1 = ld::<V>(ft, reach1).shl_bytes(1);
    let st3 = ld::<V>(ft, reach3).shl_bytes(3);
    let st5 = ld::<V>(ft, reach5).shl_bytes(5);
    let st7 = ld::<V>(ft, reach7).shl_bytes(7);
    let st9 = ld::<V>(ft, reach9).shl_bytes(1);
    let st11 = ld::<V>(ft, reach11).shl_bytes(3);
    let st13 = ld::<V>(ft, reach13).shl_bytes(5);
    let st15 = ld::<V>(ft, reach15).shl_bytes(7);

    // NB: source-реструктуринг редукции (свёртка в *s, инкрементально) НЕ меняет
    // вывод LLVM — канонизирует к тем же 54 spill'ам; аллокация регистров у GCC
    // (Vectorscan) плотнее, из Rust не управляется. Оставляем структуру C.
    let lo = st0.or(st1).or(st2).or(st3).or(st4).or(st5).or(st6).or(st7);
    let hi = st8.or(st9).or(st10).or(st11).or(st12).or(st13).or(st14).or(st15);

    let mut st = s.or(lo);
    let conf0 = st.to_u64_low() ^ !0u64;
    st = st.shr_bytes(8).or(hi);
    let conf8 = st.to_u64_low() ^ !0u64;
    *s = st.shr_bytes(8);
    (conf0, conf8)
}

impl ExecCtx<'_, '_> {
    /// Диспатч SIMD-бэкенда (как в `accel`): SSSE3 / NEON / скаляр-fallback.
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

    /// Порт `fdr_engine_exec`, состояние — настоящий m128 (`V128`).
    /// # Safety: `V` вызывается только под проверенной feature (диспатч в `run`).
    unsafe fn run_simd<V: V128>(
        &mut self,
        start: usize,
        cb: &mut impl FnMut(u64, u32) -> (ScanCtl, u8),
    ) -> ExecResult {
        let mut zbuf = [Zone::EMPTY; 3];
        let nz = prepare_zones(self.buf, start, self.first_flood_detect, &mut zbuf);
        let zones = &zbuf[..nz];
        // start_state (16 байт u128) как m128; на LE память == сериализованные байты.
        let mut state = V::loadu((&self.table.start_state as *const u128).cast());
        // Инварианты цикла — считаем ОДИН раз (иначе LLVM перезагружает поля
        // self.table.* каждую итерацию, т.к. self=&mut не доказывает инвариантность).
        let ft = self.table.bytes.as_ptr().add(FT_OFFSET);
        let dm = self.table.domain_mask;
        let stride = self.table.stride;

        // Two-phase: горячий цикл собирает кандидат-блоки (conf≠0) в ЛОКАЛЬНЫЙ
        // стековый буфер — LLVM знает, что он не алиасит data/ft, поэтому НЕ
        // пессимизирует scan из-за confirm-callback (root-cause, доказан
        // scan-only экспериментом). confirm выносится в flush: по заполнении
        // буфера, перед flood и в конце зоны — порядок (позиция↑, conf0<conf8,
        // кандидаты<flood) сохраняется.
        //
        // feature `fused_confirm` — ДИАГНОСТИЧЕСКИЙ контроль (не production):
        // немедленный do_confirm внутри scan-цикла, без записи в candidate-буфер.
        // Тот же do_confirm/conf_with_bit/SIMD scan. Изолирует стоимость staging
        // (two-phase minus fused) от flush/confirm-integration (fused minus GCC).
        #[cfg(not(feature = "fused_confirm"))]
        const CAP: usize = 64;
        #[cfg(not(feature = "fused_confirm"))]
        let mut cbuf: [(usize, u64, u64); CAP] = [(0, 0, 0); CAP];

        for z in zones {
            let data = z.data(self.buf);
            debug_assert!(z.shift <= 15);
            // variable_byte_shift_m128(state, shift) + OR zone_or_mask[shift]
            state = state.shl_bytes(z.shift);
            state = state.or(zone_or_mask::<V>(z.shift));

            let mut try_flood = z.flood_from;
            let mut it = z.start;
            #[cfg(not(feature = "fused_confirm"))]
            let mut n = 0usize;
            while it + ITER_BYTES <= z.end {
                if it > try_flood {
                    // flush накопленных кандидатов ДО flood (порядок позиций).
                    #[cfg(not(feature = "fused_confirm"))]
                    {
                        if self.flush_candidates(&cbuf[..n], data, z.adjust, cb) {
                            return ExecResult::Terminated;
                        }
                        n = 0;
                    }
                    // только main-зона: data == self.buf
                    try_flood = self.flood_detect(&mut it, try_flood, cb);
                    if self.control == 0 {
                        return ExecResult::Terminated;
                    }
                }
                let (conf0, conf8) = get_conf_stride::<V>(ft, dm, stride, data, it, &mut state);
                #[cfg(not(feature = "fused_confirm"))]
                if conf0 | conf8 != 0 {
                    cbuf[n] = (it, conf0, conf8);
                    n += 1;
                    if n == CAP {
                        if self.flush_candidates(&cbuf[..n], data, z.adjust, cb) {
                            return ExecResult::Terminated;
                        }
                        n = 0;
                    }
                }
                #[cfg(feature = "fused_confirm")]
                if conf0 | conf8 != 0 {
                    self.do_confirm(conf0, 0, data, it, z.adjust, cb);
                    self.do_confirm(conf8, 8, data, it, z.adjust, cb);
                    if self.control == 0 {
                        return ExecResult::Terminated;
                    }
                }
                it += ITER_BYTES;
            }
            // flush хвоста зоны.
            #[cfg(not(feature = "fused_confirm"))]
            if self.flush_candidates(&cbuf[..n], data, z.adjust, cb) {
                return ExecResult::Terminated;
            }
        }
        ExecResult::Completed
    }

    /// Фаза 2: confirm собранных кандидат-блоков в порядке сбора (позиция↑,
    /// conf0 перед conf8 — как в исходном одном проходе). true = терминировано.
    #[inline]
    fn flush_candidates(
        &mut self,
        cands: &[(usize, u64, u64)],
        data: &[u8],
        adjust: isize,
        cb: &mut impl FnMut(u64, u32) -> (ScanCtl, u8),
    ) -> bool {
        for &(it, conf0, conf8) in cands {
            self.do_confirm(conf0, 0, data, it, adjust, cb);
            self.do_confirm(conf8, 8, data, it, adjust, cb);
            if self.control == 0 {
                return true;
            }
        }
        false
    }

    /// Порт `do_confirm_fdr` (в C — static inline в fdr_engine_exec).
    /// `#[inline(always)]`: вызывается на каждый кандидат из flush; без инлайна — call +
    /// маршалинг 6 аргументов, и LLVM не оптимизирует через границу scan↔confirm
    /// (Clang вкомпиливает confirm → лучше аллокация; урок как с run_program).
    #[inline(always)]
    fn do_confirm(
        &mut self,
        mut conf: u64,
        offset: usize,
        data: &[u8],
        it: usize,
        adjust: isize,
        cb: &mut impl FnMut(u64, u32) -> (ScanCtl, u8),
    ) {
        if conf == 0 {
            return;
        }
        let conf_base = self.table.conf_offset;
        let b = self.table.bytes;
        while conf != 0 {
            let bit = conf.trailing_zeros() as usize;
            conf &= conf - 1;
            let byte = bit / NUM_CONF_BUCKETS + offset;
            let idx = bit % NUM_CONF_BUCKETS;
            // conf_base валиден (parse), idx<8; cf/fdrc из CRC-целого байткода.
            let cf = unsafe { u32_at(b, conf_base + idx * 4) };
            if cf == 0 {
                continue;
            }
            let fdrc = conf_base + cf as usize;
            let groups = unsafe { u64_at(b, fdrc + 24) };
            if groups & self.control == 0 {
                continue;
            }
            // confVal: 8 байт, оканчивающихся на кандидата. main-зона: it≥16 →
            // it+byte-7≥9; краевые зоны — 16 байт истории в начале бокса.
            let conf_val = unsafe { u64_at(data, (it + byte).wrapping_sub(7)) };
            // позиция в основном буфере
            let i_main = (it + byte) as isize + adjust;
            debug_assert!(i_main >= 0 && (i_main as usize) < self.buf.len());
            let squash = self.conf_with_bit(fdrc, i_main as usize, conf_val, cb);
            if squash != 0 {
                // INCLUDED_JUMP: гасим бакеты child в текущем байт-группе conf,
                // чтобы FDR-цикл не подтвердил вложенный литерал второй раз.
                conf &= !((squash as u64) << (bit & !7usize));
            }
        }
    }

    /// Порт `confWithBit`: хэш → цепочка LitInfo → отчёты.
    #[inline(always)]
    fn conf_with_bit(
        &mut self,
        fdrc: usize,
        i: usize,
        conf_key: u64,
        cb: &mut impl FnMut(u64, u32) -> (ScanCtl, u8),
    ) -> u8 {
        let mut squash = 0u8;
        let b = self.table.bytes;
        // FDRConfirm/LitInfo-оффсеты из CRC-целого байткода → unchecked hot-path.
        let (andmsk, mult, n_bits) = unsafe {
            (u64_at(b, fdrc), u64_at(b, fdrc + 8), u32_at(b, fdrc + 16))
        };
        if n_bits == 0 || n_bits >= 64 {
            return squash;
        }
        let c = ((conf_key & andmsk).wrapping_mul(mult)) >> (64 - n_bits);
        // litIndex: u32-таблица сразу после FDRConfirm (32 байта)
        let start = unsafe { u32_at(b, fdrc + 32 + c as usize * 4) };
        if start == 0 {
            return squash;
        }
        let mut li = fdrc + start as usize;
        loop {
            // Ленивая загрузка полей LitInfo (как C confWithBit): большинство
            // FP-кандидатов отваливаются на первой проверке (msk) → не грузим
            // groups/id/size зря. Профиль: eager-разбор давал лишние загрузки.
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
                    // переполнение влево (loc < buf): в block mode истории нет
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
                    self.control = match ctl {
                        ScanCtl::Continue => ALL_GROUPS,
                        ScanCtl::Terminate => 0,
                    };
                }
            }
            if next == 0 {
                return squash;
            }
            li += LIT_INFO_SIZE;
        }
    }

    /// Порт `floodDetect` (64-битная ветка). Вызывается только в main-зоне
    /// (координаты зоны == координаты буфера).
    fn flood_detect(
        &mut self,
        it: &mut usize,
        _try_flood: usize,
        cb: &mut impl FnMut(u64, u32) -> (ScanCtl, u8),
    ) -> usize {
        let buf = self.buf;
        let len = buf.len();
        let b = self.table.bytes;
        let addr = buf.as_ptr() as usize;
        let rup = |i: usize| ((addr + i + 7) & !7) - addr;
        let ld = |i: usize| u64_le(buf, i).unwrap_or(0);

        let main_loop_len = if len > 2 * ITER_BYTES {
            len - 2 * ITER_BYTES
        } else {
            0
        };
        let i = *it;
        let mut j = i;

        let c = buf[i];
        let f_base = self.table.flood_offset;
        let f_idx = u32_le(b, f_base + c as usize * 4).unwrap_or(0) as usize;
        let fl = f_base + 256 * 4 + f_idx * FLOOD_STRUCT_SIZE;

        let mut cmp_val = c as u64;
        cmp_val |= cmp_val << 8;
        cmp_val |= cmp_val << 16;
        cmp_val |= cmp_val << 32;
        let probe = ld(rup(i));

        let id_count = u16_le(b, fl + 12).unwrap_or(u16::MAX);
        let fl_suffix = u32_le(b, fl + 8).unwrap_or(0) as usize;

        'flood: {
            if probe != cmp_val || id_count >= FDR_FLOOD_MAX_IDS {
                self.flood_backoff *= 2;
                break 'flood;
            }
            if i < fl_suffix + 7 {
                self.flood_backoff *= 2;
                break 'flood;
            }
            j = i - fl_suffix;
            // откат j до 8-выровненного адреса
            j -= (addr + j) & 0x7;
            while j + 32 < main_loop_len {
                if ld(j) != cmp_val
                    || ld(j + 8) != cmp_val
                    || ld(j + 16) != cmp_val
                    || ld(j + 24) != cmp_val
                {
                    break;
                }
                j += 32;
            }
            while j + 8 < main_loop_len {
                if ld(j) != cmp_val {
                    break;
                }
                j += 8;
            }
            while j < main_loop_len {
                if buf[j] != c {
                    break;
                }
                j += 1;
            }
            if j > i {
                j -= 1; // needed for some reaches
                let iters_ahead = (j - i) / ITER_BYTES;
                let flood_size = iters_ahead * ITER_BYTES;

                let all_groups = u64_le(b, fl).unwrap_or(0);
                if id_count > 0 && self.control & all_groups != 0 {
                    // Развёртки C по idCount эквивалентны плоскому циклу
                    // позиция-затем-id (см. flood_runtime.h): порядок отчётов
                    // и поведение после Terminate совпадают.
                    let mut t = 0;
                    while t < flood_size && self.control & all_groups != 0 {
                        for k in 0..id_count as usize {
                            let gr = u64_le(b, fl + 80 + k * 8).unwrap_or(0);
                            if self.control & gr != 0 {
                                let id = u32_le(b, fl + 16 + k * 4).unwrap_or(0);
                                // Флуд = повторяющийся одиночный символ; вложенных
                                // литералов нет → squash игнорируем.
                                let (ctl, _sq) = cb((i + t) as u64, id);
                                self.control = match ctl {
                                    ScanCtl::Continue => ALL_GROUPS,
                                    ScanCtl::Terminate => 0,
                                };
                            }
                        }
                        t += 1;
                    }
                }
                *it += flood_size;
            } else {
                self.flood_backoff *= 2;
            }
        }

        // floodout: следующая точка пробы
        if main_loop_len >= 128
            && (j + self.flood_backoff as usize) < main_loop_len - 128
        {
            i.max(j) + self.flood_backoff as usize
        } else {
            main_loop_len
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// ДИАГНОСТИКА (confirm-replay эксперимент, feature `confirm_replay`, off по
// умолчанию). Изолирует confirm-путь от scan: (1) дамп main-зонных кандидатов
// одним проходом scan, (2) replay того же do_confirm/conf_with_bit по дампу
// без scan. C-двойник (Clang) читает тот же on-disk формат — чистое сравнение
// frontend/IR rustc vs clang при одинаковом LLVM-бэкенде.
// ─────────────────────────────────────────────────────────────────────────
#[cfg(feature = "confirm_replay")]
impl<'a> FdrTable<'a> {
    /// Main-зонные кандидат-блоки (it, conf0, conf8) в координатах буфера
    /// (adjust=0, data==buf). Зеркалит main-зону run_simd, но записывает вместо
    /// confirm. Флуд не реплицируется — на clean-корпусе (нет 16+ повторов) он
    /// не срабатывает, поток кандидатов и state-нить идентичны прод-скану.
    pub fn dump_main_candidates(&self, buf: &[u8]) -> Vec<(u64, u64, u64)> {
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("ssse3") {
                return unsafe { self.dump_simd::<russcan_simd::V128Sse>(buf) };
            }
        }
        unsafe { self.dump_simd::<russcan_simd::V128Scalar>(buf) }
    }

    unsafe fn dump_simd<V: V128>(&self, buf: &[u8]) -> Vec<(u64, u64, u64)> {
        let mut out = Vec::new();
        let ffd = next_flood_detect(buf, FLOOD_BACKOFF_START);
        let mut zbuf = [Zone::EMPTY; 3];
        let nz = prepare_zones(buf, 0, ffd, &mut zbuf);
        let ft = self.bytes.as_ptr().add(FT_OFFSET);
        let dm = self.domain_mask;
        let stride = self.stride;
        let mut state = V::loadu((&self.start_state as *const u128).cast());
        for z in &zbuf[..nz] {
            let data = z.data(buf);
            state = state.shl_bytes(z.shift);
            state = state.or(zone_or_mask::<V>(z.shift));
            let record = !z.is_copied; // только main-зона: data==buf, adjust==0
            let mut it = z.start;
            while it + ITER_BYTES <= z.end {
                let (c0, c8) = get_conf_stride::<V>(ft, dm, stride, data, it, &mut state);
                if record && (c0 | c8) != 0 {
                    out.push((it as u64, c0, c8));
                }
                it += ITER_BYTES;
            }
        }
        out
    }

    /// Replay confirm по дампу, `reps` раз. Тот же `do_confirm`/`conf_with_bit`.
    /// Checksum по (offset,id) колбэка — анти-DCE (на clean колбэк не зовётся,
    /// но ветка к нему зависит от загруженных данных → FP-reject работа жива).
    pub fn confirm_replay(&self, buf: &[u8], cands: &[(u64, u64, u64)], reps: usize) -> u64 {
        let mut checksum = 0u64;
        let mut ctx = ExecCtx {
            table: self,
            buf,
            control: ALL_GROUPS,
            last_match: INVALID_MATCH_ID,
            flood_backoff: FLOOD_BACKOFF_START,
            first_flood_detect: 0,
        };
        let mut cb = |i: u64, id: u32| {
            checksum = checksum
                .wrapping_add(i.rotate_left(7) ^ id as u64)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15);
            (ScanCtl::Continue, 0u8)
        };
        for _ in 0..reps {
            for &(it, c0, c8) in cands {
                ctx.do_confirm(c0, 0, buf, it as usize, 0, &mut cb);
                ctx.do_confirm(c8, 8, buf, it as usize, 0, &mut cb);
            }
        }
        drop(cb);
        checksum
    }
}
