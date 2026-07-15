//! aarch64-бэкенд: NEON (базовый для всех целевых arm-платформ).
//!
//! comparemask — трюк с `vshrn` по образу апстримного
//! `util/supervector/arch/arm/impl.cpp`: 4 бита на лейн в u64.

use core::arch::aarch64::*;

use crate::{LaneMask, V128};

#[derive(Copy, Clone)]
pub struct V128Neon(uint8x16_t);

/// vextq_u8 требует литеральный imm — таблица через match.
macro_rules! vext_table {
    ($a:expr, $b:expr, $n:expr) => {
        match $n {
            1 => vextq_u8($a, $b, 1),
            2 => vextq_u8($a, $b, 2),
            3 => vextq_u8($a, $b, 3),
            4 => vextq_u8($a, $b, 4),
            5 => vextq_u8($a, $b, 5),
            6 => vextq_u8($a, $b, 6),
            7 => vextq_u8($a, $b, 7),
            8 => vextq_u8($a, $b, 8),
            9 => vextq_u8($a, $b, 9),
            10 => vextq_u8($a, $b, 10),
            11 => vextq_u8($a, $b, 11),
            12 => vextq_u8($a, $b, 12),
            13 => vextq_u8($a, $b, 13),
            14 => vextq_u8($a, $b, 14),
            15 => vextq_u8($a, $b, 15),
            _ => unreachable!(),
        }
    };
}

impl V128Neon {
    /// u64-маска: нибл j = 0xf, если старший бит лейна j установлен (для
    /// векторов сравнения 0x00/0xff — если лейн "истинный").
    #[inline(always)]
    unsafe fn movemask_nibbles(v: uint8x16_t) -> u64 {
        let n = vshrn_n_u16(vreinterpretq_u16_u8(v), 4);
        vget_lane_u64(vreinterpret_u64_u8(n), 0)
    }
}

impl V128 for V128Neon {
    type Mask = LaneMask<4>;
    const ALL: LaneMask<4> = LaneMask::<4>::ALL16;

    #[inline(always)]
    unsafe fn loadu(ptr: *const u8) -> Self {
        V128Neon(vld1q_u8(ptr))
    }

    #[inline(always)]
    unsafe fn splat(b: u8) -> Self {
        V128Neon(vdupq_n_u8(b))
    }

    #[inline(always)]
    unsafe fn splat_u64(x: u64) -> Self {
        V128Neon(vreinterpretq_u8_u64(vdupq_n_u64(x)))
    }

    #[inline(always)]
    unsafe fn set_low_u64(x: u64) -> Self {
        V128Neon(vreinterpretq_u8_u64(vcombine_u64(
            vcreate_u64(x),
            vcreate_u64(0),
        )))
    }

    #[inline(always)]
    unsafe fn load_low64(ptr: *const u8) -> Self {
        // vld1_u64 читает 8 байт в d-регистр, combine с нулём в старшую половину.
        V128Neon(vreinterpretq_u8_u64(vcombine_u64(
            vld1_u64(ptr as *const u64),
            vcreate_u64(0),
        )))
    }

    #[inline(always)]
    unsafe fn to_u64_low(self) -> u64 {
        vgetq_lane_u64(vreinterpretq_u64_u8(self.0), 0)
    }

    #[inline(always)]
    unsafe fn zeroes() -> Self {
        V128Neon(vdupq_n_u8(0))
    }

    #[inline(always)]
    unsafe fn ones() -> Self {
        V128Neon(vdupq_n_u8(0xff))
    }

    #[inline(always)]
    unsafe fn and(self, o: Self) -> Self {
        V128Neon(vandq_u8(self.0, o.0))
    }

    #[inline(always)]
    unsafe fn or(self, o: Self) -> Self {
        V128Neon(vorrq_u8(self.0, o.0))
    }

    #[inline(always)]
    unsafe fn xor(self, o: Self) -> Self {
        V128Neon(veorq_u8(self.0, o.0))
    }

    #[inline(always)]
    unsafe fn and_not(self, o: Self) -> Self {
        // vbicq_u8(a, b) = a & !b
        V128Neon(vbicq_u8(self.0, o.0))
    }

    #[inline(always)]
    unsafe fn shr64_by4(self) -> Self {
        V128Neon(vreinterpretq_u8_u64(vshrq_n_u64(
            vreinterpretq_u64_u8(self.0),
            4,
        )))
    }

    #[inline(always)]
    unsafe fn pshufb(self, idx: Self) -> Self {
        // Точная x86-семантика: биты 4..6 игнорируем, бит 7 — обнуление.
        // idx & 0x8f: лейны с битом 7 дают индекс >= 16 -> vqtbl1q зануляет.
        let masked = vandq_u8(idx.0, vdupq_n_u8(0x8f));
        V128Neon(vqtbl1q_u8(self.0, masked))
    }

    #[inline(always)]
    unsafe fn eq(self, o: Self) -> Self {
        V128Neon(vceqq_u8(self.0, o.0))
    }

    #[inline(always)]
    unsafe fn eq_mask(self, o: Self) -> LaneMask<4> {
        LaneMask::from_bits(Self::movemask_nibbles(vceqq_u8(self.0, o.0)))
    }

    #[inline(always)]
    unsafe fn nonzero_mask(self) -> LaneMask<4> {
        let z = Self::movemask_nibbles(vceqq_u8(self.0, vdupq_n_u8(0)));
        LaneMask::from_bits(!z)
    }

    #[inline(always)]
    unsafe fn alignr_15(self, low: Self) -> Self {
        V128Neon(vextq_u8(low.0, self.0, 15))
    }

    #[inline(always)]
    unsafe fn shl_bytes(self, n: usize) -> Self {
        debug_assert!(n <= 16);
        match n {
            0 => self,
            16 => V128Neon(vdupq_n_u8(0)),
            k => V128Neon(vext_table!(vdupq_n_u8(0), self.0, 16 - k)),
        }
    }

    #[inline(always)]
    unsafe fn shr_bytes(self, n: usize) -> Self {
        debug_assert!(n <= 16);
        match n {
            0 => self,
            16 => V128Neon(vdupq_n_u8(0)),
            k => V128Neon(vext_table!(self.0, vdupq_n_u8(0), k)),
        }
    }

    #[inline(always)]
    unsafe fn to_array(self) -> [u8; 16] {
        let mut r = [0u8; 16];
        vst1q_u8(r.as_mut_ptr(), self.0);
        r
    }
}
