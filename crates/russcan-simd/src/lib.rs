//! SIMD-слой russcan: порт `util/supervector` + accel-примитивов vectorscan.
//!
//! Весь unsafe-SIMD проекта живёт в этом крейте (Д5 плана). Алгоритмы
//! (shufti/truffle/vermicelli — порт `nfa/*_simd.hpp` апстрима) написаны
//! генериками поверх трейта [`V128`]; бэкенды: NEON (aarch64), SSE2+SSSE3
//! (x86_64), скалярный fallback. Скалярный бэкенд гоняет тот же генерик-код,
//! поэтому служит референсом в property-тестах и путём для Miri.
//!
//! Референс: vectorscan @ a1c107e, `src/util/supervector/`, `src/nfa/{x86,arm}/`.

pub mod accel;

mod scalar;
pub use scalar::V128Scalar;

#[cfg(target_arch = "x86_64")]
mod x86;
#[cfg(target_arch = "x86_64")]
pub use x86::V128Sse;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::V128Neon;

/// Маска совпадений по 16 лейнам вектора, `STRIDE` бит на лейн.
///
/// x86 `movemask` даёт 1 бит на лейн; NEON-трюк с `vshrn` — 4 бита на лейн
/// (апстримный `SuperVector::comparemask` с `mask_width()`). Скаляр — 1 бит.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LaneMask<const STRIDE: u32> {
    bits: u64,
}

/// Операции над маской лейнов — то, что нужно алгоритмам в [`accel`].
pub trait MaskOps: Copy {
    fn any(self) -> bool;
    /// Индекс первого (младшего) лейна с совпадением.
    fn first(self) -> Option<u32>;
    /// Индекс последнего (старшего) лейна с совпадением.
    fn last(self) -> Option<u32>;
    /// Оставить только лейны с индексом < `n` (границы неполных блоков).
    fn keep_lanes_below(self, n: u32) -> Self;
    /// Оставить только лейны с индексом >= `n`.
    fn keep_lanes_from(self, n: u32) -> Self;
    /// Инверсия в пределах лейнов `all` (для "!= 0" из "== 0").
    fn invert_within(self, all: Self) -> Self;
}

impl<const STRIDE: u32> LaneMask<STRIDE> {
    pub const NONE: Self = Self { bits: 0 };
    pub const ALL16: Self = Self {
        bits: if STRIDE as usize * 16 >= 64 {
            !0u64
        } else {
            (1u64 << (STRIDE * 16)) - 1
        },
    };

    #[inline(always)]
    pub fn from_bits(bits: u64) -> Self {
        Self { bits }
    }
}

impl<const STRIDE: u32> MaskOps for LaneMask<STRIDE> {
    #[inline(always)]
    fn any(self) -> bool {
        self.bits != 0
    }

    #[inline(always)]
    fn first(self) -> Option<u32> {
        if self.bits == 0 {
            None
        } else {
            Some(self.bits.trailing_zeros() / STRIDE)
        }
    }

    #[inline(always)]
    fn last(self) -> Option<u32> {
        if self.bits == 0 {
            None
        } else {
            Some((63 - self.bits.leading_zeros()) / STRIDE)
        }
    }

    #[inline(always)]
    fn keep_lanes_below(self, n: u32) -> Self {
        let width = n * STRIDE;
        let m = if width >= 64 { !0u64 } else { (1u64 << width) - 1 };
        Self { bits: self.bits & m }
    }

    #[inline(always)]
    fn keep_lanes_from(self, n: u32) -> Self {
        let width = n * STRIDE;
        let m = if width >= 64 { 0 } else { !((1u64 << width) - 1) };
        Self { bits: self.bits & m }
    }

    #[inline(always)]
    fn invert_within(self, all: Self) -> Self {
        Self {
            bits: !self.bits & all.bits,
        }
    }
}

/// Итератор по индексам взведённых лейнов (по возрастанию).
pub struct LaneIter<const STRIDE: u32> {
    bits: u64,
}

impl<const STRIDE: u32> Iterator for LaneIter<STRIDE> {
    type Item = u32;

    #[inline(always)]
    fn next(&mut self) -> Option<u32> {
        if self.bits == 0 {
            return None;
        }
        let lane = self.bits.trailing_zeros() / STRIDE;
        let lane_mask = ((1u128 << STRIDE) - 1) as u64;
        self.bits &= !(lane_mask << (lane * STRIDE));
        Some(lane)
    }
}

impl<const STRIDE: u32> IntoIterator for LaneMask<STRIDE> {
    type Item = u32;
    type IntoIter = LaneIter<STRIDE>;

    #[inline(always)]
    fn into_iter(self) -> LaneIter<STRIDE> {
        LaneIter { bits: self.bits }
    }
}

/// 128-битный вектор — порт интерфейса `SuperVector<16>` апстрима.
///
/// # Safety
///
/// Методы `unsafe`, потому что конкретные реализации требуют доступности
/// своего ISA (SSSE3 / NEON) — это гарантируют диспатчеры в [`accel`]
/// (runtime-детект + `#[target_feature]`-обёртки). `loadu` дополнительно
/// требует валидного указателя на 16 читаемых байт.
/// Контракт unsafe: каждый метод требует, чтобы ISA бэкенда была доступна
/// на текущем CPU (см. заголовок трейта); `loadu` дополнительно требует
/// валидный указатель. Вызывать только из-под `#[target_feature]`-обёрток
/// диспатчера или для заведомо безопасного бэкенда (скаляр, NEON на aarch64).
pub trait V128: Copy {
    type Mask: MaskOps;
    /// Маска "все 16 лейнов".
    const ALL: Self::Mask;

    /// # Safety: `ptr` — валидные 16 читаемых байт.
    unsafe fn loadu(ptr: *const u8) -> Self;

    unsafe fn splat(b: u8) -> Self;
    unsafe fn splat_u64(x: u64) -> Self;
    unsafe fn zeroes() -> Self;
    unsafe fn ones() -> Self;

    /// Загрузить u64 в НИЗКИЕ 64 бита, высокие = 0 (C: `load_m128_from_u64a`).
    /// В отличие от `splat_u64`, высокая полоса зануляется.
    unsafe fn set_low_u64(x: u64) -> Self;
    /// Прямая загрузка 8 байт из памяти в НИЗКИЕ 64 бита (высокие = 0),
    /// без round-trip через GPR (C: `_mm_loadl_epi64`). Критично для FDR:
    /// избегает cross-domain move на каждой из 16 table-lookup за итерацию.
    /// # Safety: `ptr` — валидные 8 читаемых байт.
    unsafe fn load_low64(ptr: *const u8) -> Self;
    /// Извлечь низкие 64 бита вектора (C: `movq`).
    unsafe fn to_u64_low(self) -> u64;

    unsafe fn and(self, o: Self) -> Self;
    unsafe fn or(self, o: Self) -> Self;
    unsafe fn xor(self, o: Self) -> Self;
    /// `self & !o` (в терминах C: `andnot(o, self)`).
    unsafe fn and_not(self, o: Self) -> Self;

    /// Сдвиг каждой u64-полосы вправо на 4 бита — апстримный `vshr_64_imm<4>`.
    /// Биты «перетекают» между соседними байтами внутри полосы; вызывающие
    /// маскируют результат (`& 0x0f`), как и C-код.
    unsafe fn shr64_by4(self) -> Self;

    /// pshufb с точной x86-семантикой: бит 7 байта-индекса обнуляет лейн,
    /// биты 4..6 игнорируются, индекс — младшие 4 бита.
    unsafe fn pshufb(self, idx: Self) -> Self;

    unsafe fn eq(self, o: Self) -> Self;
    unsafe fn eq_mask(self, o: Self) -> Self::Mask;
    /// Лейны, в которых байт != 0.
    unsafe fn nonzero_mask(self) -> Self::Mask;

    /// `concat(low, self)` со сдвигом на 15: байт i результата =
    /// `concat[i + 15]`, т.е. байт 0 = `low[15]`, байты 1..16 = `self[0..15]`.
    /// Апстримный `self.alignr(low, 15)`.
    unsafe fn alignr_15(self, low: Self) -> Self;

    /// Сдвиг вектора влево на n БАЙТ (к старшим лейнам), 0 <= n <= 16.
    unsafe fn shl_bytes(self, n: usize) -> Self;
    /// Сдвиг вектора вправо на n БАЙТ (к младшим лейнам), 0 <= n <= 16.
    unsafe fn shr_bytes(self, n: usize) -> Self;

    unsafe fn to_array(self) -> [u8; 16];

    /// Лейны, в которых `self != o`.
    #[inline(always)]
    unsafe fn neq_mask(self, o: Self) -> Self::Mask {
        self.eq_mask(o).invert_within(Self::ALL)
    }

    /// Загрузка `slice.len() <= 16` байт с занулением хвоста, без OOB-чтений.
    #[inline(always)]
    unsafe fn load_partial(slice: &[u8]) -> Self {
        debug_assert!(slice.len() <= 16);
        let mut tmp = [0u8; 16];
        tmp[..slice.len()].copy_from_slice(slice);
        Self::loadu(tmp.as_ptr())
    }
}
