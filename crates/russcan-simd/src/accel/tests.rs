//! Property-тесты: диспатченный SIMD-путь против наивного референса и
//! против генерика на скалярном бэкенде. Буферы гоняются по всем сдвигам
//! выравнивания, чтобы покрыть head/aligned/tail-ветки скана.

use super::{generic, masks, reference};
use crate::V128Scalar;

/// xorshift64* — детерминированный RNG без зависимостей.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 32) as u8
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Буфер со случайным наполнением и «подсадкой» интересных байтов.
fn make_buf(rng: &mut Rng, len: usize, plant: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
    if !v.is_empty() {
        for &p in plant {
            let at = rng.below(v.len());
            v[at] = p;
        }
    }
    v
}

/// Прогон одного кейса по всем сдвигам выравнивания 0..16.
fn for_alignments(buf: &[u8], mut check: impl FnMut(&[u8])) {
    let mut padded = vec![0u8; buf.len() + 32];
    for off in 0..16 {
        padded[off..off + buf.len()].copy_from_slice(buf);
        check(&padded[off..off + buf.len()]);
    }
}

const LENS: &[usize] = &[0, 1, 2, 5, 15, 16, 17, 31, 32, 33, 47, 64, 100, 257];

#[test]
fn vermicelli_family_vs_reference() {
    let mut rng = Rng::new(0xdead_beef);
    for &len in LENS {
        for _ in 0..40 {
            let c = rng.byte();
            let nocase = rng.next() & 1 == 0;
            let buf = make_buf(&mut rng, len, &[c, c ^ 0x20, !c]);
            for_alignments(&buf, |b| {
                assert_eq!(
                    super::vermicelli_exec(c, nocase, b),
                    reference::verm_fwd(c, nocase, b),
                    "verm c={c:#x} nocase={nocase} len={len}"
                );
                assert_eq!(
                    super::nvermicelli_exec(c, nocase, b),
                    reference::nverm_fwd(c, nocase, b),
                    "nverm c={c:#x} nocase={nocase} len={len}"
                );
                assert_eq!(
                    super::rvermicelli_exec(c, nocase, b),
                    reference::verm_rev(c, nocase, b),
                    "rverm c={c:#x} nocase={nocase} len={len}"
                );
                assert_eq!(
                    super::rnvermicelli_exec(c, nocase, b),
                    reference::nverm_rev(c, nocase, b),
                    "rnverm c={c:#x} nocase={nocase} len={len}"
                );
            });
        }
    }
}

/// Класс с <= 8 различных старших ниблов (кодируется shufti точно).
fn gen_shufti_class(rng: &mut Rng) -> Vec<u8> {
    loop {
        let n = 1 + rng.below(12);
        let class: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
        let mut nibs: Vec<u8> = class.iter().map(|&c| c >> 4).collect();
        nibs.sort_unstable();
        nibs.dedup();
        if nibs.len() <= 8 {
            return class;
        }
    }
}

#[test]
fn shufti_vs_reference() {
    let mut rng = Rng::new(0x5817_f00d);
    for &len in LENS {
        for _ in 0..40 {
            let class = gen_shufti_class(&mut rng);
            let (lo, hi) = masks::shufti_masks_exact(&class).unwrap();
            let buf = make_buf(&mut rng, len, &class);
            for_alignments(&buf, |b| {
                assert_eq!(
                    super::shufti_exec(&lo, &hi, b),
                    reference::shufti_fwd(&lo, &hi, b),
                    "shufti class={class:02x?} len={len}"
                );
                assert_eq!(
                    super::rshufti_exec(&lo, &hi, b),
                    reference::shufti_rev(&lo, &hi, b),
                    "rshufti class={class:02x?} len={len}"
                );
            });
        }
    }
}

#[test]
fn shufti_exact_masks_match_class_semantics() {
    // Сборщик масок и предикат согласованы: по всем 256 байтам.
    let mut rng = Rng::new(0xc1a5_5e5);
    for _ in 0..200 {
        let class = gen_shufti_class(&mut rng);
        let (lo, hi) = masks::shufti_masks_exact(&class).unwrap();
        for b in 0..=255u8 {
            assert_eq!(
                reference::shufti_in_class(&lo, &hi, b),
                class.contains(&b),
                "class={class:02x?} b={b:#x}"
            );
        }
    }
}

#[test]
fn truffle_vs_reference() {
    let mut rng = Rng::new(0x0072_ff1e_5000);
    for &len in LENS {
        for _ in 0..40 {
            let n = 1 + rng.below(40);
            let class: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
            let (clear, set) = masks::truffle_masks(&class);
            let buf = make_buf(&mut rng, len, &class);
            for_alignments(&buf, |b| {
                assert_eq!(
                    super::truffle_exec(&clear, &set, b),
                    reference::truffle_fwd(&clear, &set, b),
                    "truffle class={class:02x?} len={len}"
                );
                assert_eq!(
                    super::rtruffle_exec(&clear, &set, b),
                    reference::truffle_rev(&clear, &set, b),
                    "rtruffle class={class:02x?} len={len}"
                );
            });
        }
    }
}

#[test]
fn truffle_exact_masks_match_class_semantics() {
    let mut rng = Rng::new(0xacce1);
    for _ in 0..200 {
        let n = 1 + rng.below(40);
        let class: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
        let (clear, set) = masks::truffle_masks(&class);
        for b in 0..=255u8 {
            assert_eq!(
                reference::truffle_in_class(&clear, &set, b),
                class.contains(&b),
                "class={class:02x?} b={b:#x}"
            );
        }
    }
}

#[test]
fn shufti_double_vs_naive() {
    let mut rng = Rng::new(0xd0b1_e5);
    for &len in LENS {
        for _ in 0..60 {
            let n = 1 + rng.below(8);
            let pairs: Vec<(u8, u8)> = (0..n).map(|_| (rng.byte(), rng.byte())).collect();
            let (m1l, m1h, m2l, m2h) = masks::shufti_double_masks_exact(&pairs).unwrap();
            // подсаживаем и целые пары, и одиночные первые символы
            let mut plant = Vec::new();
            for &(a, b) in &pairs {
                plant.push(a);
                plant.push(b);
            }
            let mut buf = make_buf(&mut rng, len, &plant);
            if len >= 2 {
                let (a, b) = pairs[rng.below(pairs.len())];
                let at = rng.below(buf.len() - 1);
                buf[at] = a;
                buf[at + 1] = b;
            }
            for_alignments(&buf, |bb| {
                assert_eq!(
                    super::shufti_double_exec(&m1l, &m1h, &m2l, &m2h, bb),
                    masks::shufti_double_naive(&pairs, bb),
                    "dshufti pairs={pairs:02x?} len={len} buf={bb:02x?}"
                );
            });
        }
    }
}

/// Диспатченный SIMD-путь бит-в-бит совпадает с генериком на скаляре
/// (та же логика, другой бэкенд) — ловит расхождения реализаций V128.
#[test]
fn simd_backend_equals_scalar_backend() {
    let mut rng = Rng::new(0xbac_c0de);
    for &len in LENS {
        for _ in 0..20 {
            let class = gen_shufti_class(&mut rng);
            let (lo, hi) = masks::shufti_masks_exact(&class).unwrap();
            let (clear, set) = masks::truffle_masks(&class);
            let c = rng.byte();
            let buf = make_buf(&mut rng, len, &class);
            for_alignments(&buf, |b| unsafe {
                assert_eq!(
                    super::shufti_exec(&lo, &hi, b),
                    generic::shufti_exec::<V128Scalar>(&lo, &hi, b),
                );
                assert_eq!(
                    super::rshufti_exec(&lo, &hi, b),
                    generic::rshufti_exec::<V128Scalar>(&lo, &hi, b),
                );
                assert_eq!(
                    super::truffle_exec(&clear, &set, b),
                    generic::truffle_exec::<V128Scalar>(&clear, &set, b),
                );
                assert_eq!(
                    super::rtruffle_exec(&clear, &set, b),
                    generic::rtruffle_exec::<V128Scalar>(&clear, &set, b),
                );
                assert_eq!(
                    super::vermicelli_exec(c, true, b),
                    generic::vermicelli_exec::<V128Scalar>(c, true, b),
                );
                assert_eq!(
                    super::rnvermicelli_exec(c, false, b),
                    generic::rnvermicelli_exec::<V128Scalar>(c, false, b),
                );
            });
        }
    }
}

/// Прямые тесты операций V128: нативный бэкенд против скалярного.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod backend_ops {
    use super::Rng;
    use crate::{MaskOps, V128, V128Scalar};

    #[cfg(target_arch = "x86_64")]
    type Native = crate::V128Sse;
    #[cfg(target_arch = "aarch64")]
    type Native = crate::V128Neon;

    fn rand_vec(rng: &mut Rng) -> [u8; 16] {
        core::array::from_fn(|_| rng.byte())
    }

    #[test]
    fn ops_match_scalar() {
        #[cfg(target_arch = "x86_64")]
        if !std::arch::is_x86_feature_detected!("ssse3") {
            eprintln!("skip: нет SSSE3");
            return;
        }
        let mut rng = Rng::new(0x0b5);
        for _ in 0..500 {
            let a = rand_vec(&mut rng);
            let b = rand_vec(&mut rng);
            let n = rng.below(17);
            // SAFETY: ISA проверена выше (SSSE3) либо гарантирована (NEON).
            unsafe {
                let (na, nb) = (Native::loadu(a.as_ptr()), Native::loadu(b.as_ptr()));
                let (sa, sb) = (
                    V128Scalar::loadu(a.as_ptr()),
                    V128Scalar::loadu(b.as_ptr()),
                );
                assert_eq!(na.and(nb).to_array(), sa.and(sb).to_array());
                assert_eq!(na.or(nb).to_array(), sa.or(sb).to_array());
                assert_eq!(na.xor(nb).to_array(), sa.xor(sb).to_array());
                assert_eq!(na.and_not(nb).to_array(), sa.and_not(sb).to_array());
                assert_eq!(na.shr64_by4().to_array(), sa.shr64_by4().to_array());
                assert_eq!(na.pshufb(nb).to_array(), sa.pshufb(sb).to_array());
                assert_eq!(na.eq(nb).to_array(), sa.eq(sb).to_array());
                assert_eq!(na.alignr_15(nb).to_array(), sa.alignr_15(sb).to_array());
                assert_eq!(na.shl_bytes(n).to_array(), sa.shl_bytes(n).to_array());
                assert_eq!(na.shr_bytes(n).to_array(), sa.shr_bytes(n).to_array());
                assert_eq!(na.eq_mask(nb).first(), sa.eq_mask(sb).first());
                assert_eq!(na.eq_mask(nb).last(), sa.eq_mask(sb).last());
                assert_eq!(na.nonzero_mask().first(), sa.nonzero_mask().first());
                assert_eq!(na.nonzero_mask().last(), sa.nonzero_mask().last());
                assert_eq!(na.neq_mask(nb).first(), sa.neq_mask(sb).first());
                assert_eq!(
                    Native::splat_u64(0x8040201008040201).to_array(),
                    V128Scalar::splat_u64(0x8040201008040201).to_array()
                );
            }
        }
    }
}
