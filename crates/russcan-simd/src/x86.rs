//! x86_64-бэкенд: SSE2 + SSSE3 (`pshufb`, `palignr`).
//!
//! Контракт: методы можно вызывать только при доступном SSSE3 — диспатчер
//! в `accel` проверяет `is_x86_feature_detected!("ssse3")`. AVX2-вариант
//! (V256) — отдельным шагом при выравнивании перфа (гейт Ф2).

use core::arch::x86_64::*;

use crate::{LaneMask, V128};

#[derive(Copy, Clone)]
pub struct V128Sse(__m128i);

/// Таблица немедленных для байтовых сдвигов: интринсикам нужен литеральный imm8.
macro_rules! byte_shift {
    ($v:expr, $n:expr, $intr:ident) => {
        match $n {
            0 => $v,
            1 => $intr($v, 1),
            2 => $intr($v, 2),
            3 => $intr($v, 3),
            4 => $intr($v, 4),
            5 => $intr($v, 5),
            6 => $intr($v, 6),
            7 => $intr($v, 7),
            8 => $intr($v, 8),
            9 => $intr($v, 9),
            10 => $intr($v, 10),
            11 => $intr($v, 11),
            12 => $intr($v, 12),
            13 => $intr($v, 13),
            14 => $intr($v, 14),
            15 => $intr($v, 15),
            _ => _mm_setzero_si128(),
        }
    };
}

impl V128 for V128Sse {
    type Mask = LaneMask<1>;
    const ALL: LaneMask<1> = LaneMask::<1>::ALL16;

    #[inline(always)]
    unsafe fn loadu(ptr: *const u8) -> Self {
        V128Sse(_mm_loadu_si128(ptr as *const __m128i))
    }

    #[inline(always)]
    unsafe fn splat(b: u8) -> Self {
        V128Sse(_mm_set1_epi8(b as i8))
    }

    #[inline(always)]
    unsafe fn splat_u64(x: u64) -> Self {
        V128Sse(_mm_set1_epi64x(x as i64))
    }

    #[inline(always)]
    unsafe fn set_low_u64(x: u64) -> Self {
        V128Sse(_mm_cvtsi64_si128(x as i64))
    }

    #[inline(always)]
    unsafe fn load_low64(ptr: *const u8) -> Self {
        V128Sse(_mm_loadl_epi64(ptr as *const __m128i))
    }

    #[inline(always)]
    unsafe fn to_u64_low(self) -> u64 {
        _mm_cvtsi128_si64(self.0) as u64
    }

    #[inline(always)]
    unsafe fn zeroes() -> Self {
        V128Sse(_mm_setzero_si128())
    }

    #[inline(always)]
    unsafe fn ones() -> Self {
        V128Sse(_mm_set1_epi8(-1))
    }

    #[inline(always)]
    unsafe fn and(self, o: Self) -> Self {
        V128Sse(_mm_and_si128(self.0, o.0))
    }

    #[inline(always)]
    unsafe fn or(self, o: Self) -> Self {
        V128Sse(_mm_or_si128(self.0, o.0))
    }

    #[inline(always)]
    unsafe fn xor(self, o: Self) -> Self {
        V128Sse(_mm_xor_si128(self.0, o.0))
    }

    #[inline(always)]
    unsafe fn and_not(self, o: Self) -> Self {
        // _mm_andnot_si128(a, b) = !a & b
        V128Sse(_mm_andnot_si128(o.0, self.0))
    }

    #[inline(always)]
    unsafe fn shr64_by4(self) -> Self {
        V128Sse(_mm_srli_epi64(self.0, 4))
    }

    #[inline(always)]
    unsafe fn pshufb(self, idx: Self) -> Self {
        V128Sse(_mm_shuffle_epi8(self.0, idx.0))
    }

    #[inline(always)]
    unsafe fn eq(self, o: Self) -> Self {
        V128Sse(_mm_cmpeq_epi8(self.0, o.0))
    }

    #[inline(always)]
    unsafe fn eq_mask(self, o: Self) -> LaneMask<1> {
        let m = _mm_movemask_epi8(_mm_cmpeq_epi8(self.0, o.0));
        LaneMask::from_bits(m as u32 as u64)
    }

    #[inline(always)]
    unsafe fn nonzero_mask(self) -> LaneMask<1> {
        let z = _mm_movemask_epi8(_mm_cmpeq_epi8(self.0, _mm_setzero_si128()));
        LaneMask::from_bits(!(z as u32 as u64) & 0xffff)
    }

    #[inline(always)]
    unsafe fn alignr_15(self, low: Self) -> Self {
        V128Sse(_mm_alignr_epi8(self.0, low.0, 15))
    }

    #[inline(always)]
    unsafe fn shl_bytes(self, n: usize) -> Self {
        debug_assert!(n <= 16);
        V128Sse(byte_shift!(self.0, n, _mm_slli_si128))
    }

    #[inline(always)]
    unsafe fn shr_bytes(self, n: usize) -> Self {
        debug_assert!(n <= 16);
        V128Sse(byte_shift!(self.0, n, _mm_srli_si128))
    }

    #[inline(always)]
    unsafe fn to_array(self) -> [u8; 16] {
        let mut r = [0u8; 16];
        _mm_storeu_si128(r.as_mut_ptr() as *mut __m128i, self.0);
        r
    }
}
