//! Скалярный бэкенд: референс для property-тестов, путь для Miri и
//! экзотических архитектур. Семантика каждой операции — определение
//! соответствующего интринсика.

use crate::{LaneMask, V128};

#[derive(Copy, Clone, Debug)]
pub struct V128Scalar(pub [u8; 16]);

impl V128Scalar {
    #[inline(always)]
    fn map2(self, o: Self, f: impl Fn(u8, u8) -> u8) -> Self {
        let mut r = [0u8; 16];
        for i in 0..16 {
            r[i] = f(self.0[i], o.0[i]);
        }
        V128Scalar(r)
    }

    #[inline(always)]
    fn lanes_where(self, o: Self, f: impl Fn(u8, u8) -> bool) -> LaneMask<1> {
        let mut bits = 0u64;
        for i in 0..16 {
            if f(self.0[i], o.0[i]) {
                bits |= 1 << i;
            }
        }
        LaneMask::from_bits(bits)
    }
}

impl V128 for V128Scalar {
    type Mask = LaneMask<1>;
    const ALL: LaneMask<1> = LaneMask::<1>::ALL16;

    #[inline(always)]
    unsafe fn loadu(ptr: *const u8) -> Self {
        let mut r = [0u8; 16];
        core::ptr::copy_nonoverlapping(ptr, r.as_mut_ptr(), 16);
        V128Scalar(r)
    }

    #[inline(always)]
    unsafe fn splat(b: u8) -> Self {
        V128Scalar([b; 16])
    }

    #[inline(always)]
    unsafe fn splat_u64(x: u64) -> Self {
        let b = x.to_le_bytes();
        let mut r = [0u8; 16];
        r[..8].copy_from_slice(&b);
        r[8..].copy_from_slice(&b);
        V128Scalar(r)
    }

    #[inline(always)]
    unsafe fn set_low_u64(x: u64) -> Self {
        let mut r = [0u8; 16];
        r[..8].copy_from_slice(&x.to_le_bytes());
        V128Scalar(r)
    }

    #[inline(always)]
    unsafe fn load_low64(ptr: *const u8) -> Self {
        let mut r = [0u8; 16];
        core::ptr::copy_nonoverlapping(ptr, r.as_mut_ptr(), 8);
        V128Scalar(r)
    }

    #[inline(always)]
    unsafe fn to_u64_low(self) -> u64 {
        u64::from_le_bytes(self.0[..8].try_into().unwrap())
    }

    #[inline(always)]
    unsafe fn zeroes() -> Self {
        V128Scalar([0; 16])
    }

    #[inline(always)]
    unsafe fn ones() -> Self {
        V128Scalar([0xff; 16])
    }

    #[inline(always)]
    unsafe fn and(self, o: Self) -> Self {
        self.map2(o, |a, b| a & b)
    }

    #[inline(always)]
    unsafe fn or(self, o: Self) -> Self {
        self.map2(o, |a, b| a | b)
    }

    #[inline(always)]
    unsafe fn xor(self, o: Self) -> Self {
        self.map2(o, |a, b| a ^ b)
    }

    #[inline(always)]
    unsafe fn and_not(self, o: Self) -> Self {
        self.map2(o, |a, b| a & !b)
    }

    #[inline(always)]
    unsafe fn shr64_by4(self) -> Self {
        let lo = u64::from_le_bytes(self.0[..8].try_into().unwrap()) >> 4;
        let hi = u64::from_le_bytes(self.0[8..].try_into().unwrap()) >> 4;
        let mut r = [0u8; 16];
        r[..8].copy_from_slice(&lo.to_le_bytes());
        r[8..].copy_from_slice(&hi.to_le_bytes());
        V128Scalar(r)
    }

    #[inline(always)]
    unsafe fn pshufb(self, idx: Self) -> Self {
        let mut r = [0u8; 16];
        for i in 0..16 {
            let ix = idx.0[i];
            r[i] = if ix & 0x80 != 0 {
                0
            } else {
                self.0[(ix & 0x0f) as usize]
            };
        }
        V128Scalar(r)
    }

    #[inline(always)]
    unsafe fn eq(self, o: Self) -> Self {
        self.map2(o, |a, b| if a == b { 0xff } else { 0 })
    }

    #[inline(always)]
    unsafe fn eq_mask(self, o: Self) -> LaneMask<1> {
        self.lanes_where(o, |a, b| a == b)
    }

    #[inline(always)]
    unsafe fn nonzero_mask(self) -> LaneMask<1> {
        self.lanes_where(V128Scalar([0; 16]), |a, _| a != 0)
    }

    #[inline(always)]
    unsafe fn alignr_15(self, low: Self) -> Self {
        let mut r = [0u8; 16];
        r[0] = low.0[15];
        r[1..16].copy_from_slice(&self.0[..15]);
        V128Scalar(r)
    }

    #[inline(always)]
    unsafe fn shl_bytes(self, n: usize) -> Self {
        debug_assert!(n <= 16);
        let mut r = [0u8; 16];
        for i in n..16 {
            r[i] = self.0[i - n];
        }
        V128Scalar(r)
    }

    #[inline(always)]
    unsafe fn shr_bytes(self, n: usize) -> Self {
        debug_assert!(n <= 16);
        let mut r = [0u8; 16];
        for i in 0..16usize.saturating_sub(n) {
            r[i] = self.0[i + n];
        }
        V128Scalar(r)
    }

    #[inline(always)]
    unsafe fn to_array(self) -> [u8; 16] {
        self.0
    }
}
