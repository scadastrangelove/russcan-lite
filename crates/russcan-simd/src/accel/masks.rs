//! Сборка масок для ТЕСТОВ и фаззинга.
//!
//! Боевые маски приходят из байткода (их строит C++-компилятор,
//! `shufticompile.cpp`/`trufflecompile.cpp`). Здесь — минимальные точные
//! кодировки: классы, представимые без ложных срабатываний, чтобы наивный
//! референс был валидным ground truth.

/// Точные shufti-маски: бакет на каждый старший нибл (максимум 8).
/// `None`, если в классе больше 8 различных старших ниблов — такой класс
/// single-shufti без FP не кодирует (компилятор взял бы truffle).
pub fn shufti_masks_exact(class: &[u8]) -> Option<([u8; 16], [u8; 16])> {
    let mut nibbles: Vec<u8> = class.iter().map(|&c| c >> 4).collect();
    nibbles.sort_unstable();
    nibbles.dedup();
    if nibbles.len() > 8 {
        return None;
    }
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    for &c in class {
        let bucket = nibbles.iter().position(|&n| n == c >> 4).unwrap();
        lo[(c & 0xf) as usize] |= 1 << bucket;
        hi[(c >> 4) as usize] |= 1 << bucket;
    }
    Some((lo, hi))
}

/// Точные truffle-маски — кодировка полная, работает для любого класса.
pub fn truffle_masks(class: &[u8]) -> ([u8; 16], [u8; 16]) {
    let mut clear = [0u8; 16];
    let mut set = [0u8; 16];
    for &c in class {
        let m = if c < 0x80 { &mut clear } else { &mut set };
        m[(c & 0xf) as usize] |= 1 << ((c >> 4) & 7);
    }
    (clear, set)
}

/// Точные маски двойного shufti: бакет на пару (максимум 8 пар).
/// Кодировка ИНВЕРТИРОВАННАЯ (снятый бит = совпадение), как в байткоде.
pub fn shufti_double_masks_exact(
    pairs: &[(u8, u8)],
) -> Option<([u8; 16], [u8; 16], [u8; 16], [u8; 16])> {
    if pairs.len() > 8 || pairs.is_empty() {
        return None;
    }
    let mut m1_lo = [0xffu8; 16];
    let mut m1_hi = [0xffu8; 16];
    let mut m2_lo = [0xffu8; 16];
    let mut m2_hi = [0xffu8; 16];
    for (k, &(a, b)) in pairs.iter().enumerate() {
        m1_lo[(a & 0xf) as usize] &= !(1 << k);
        m1_hi[(a >> 4) as usize] &= !(1 << k);
        m2_lo[(b & 0xf) as usize] &= !(1 << k);
        m2_hi[(b >> 4) as usize] &= !(1 << k);
    }
    Some((m1_lo, m1_hi, m2_lo, m2_hi))
}

/// Наивная семантика двойного shufti для точных масок: первая пара
/// (p, p+1) из списка, иначе resume-точка `len-1`, если последний байт —
/// первый символ какой-либо пары.
pub fn shufti_double_naive(pairs: &[(u8, u8)], buf: &[u8]) -> Option<usize> {
    if buf.is_empty() {
        return None;
    }
    for p in 0..buf.len().saturating_sub(1) {
        if pairs.iter().any(|&(a, b)| buf[p] == a && buf[p + 1] == b) {
            return Some(p);
        }
    }
    let last = buf[buf.len() - 1];
    if pairs.iter().any(|&(a, _)| a == last) {
        return Some(buf.len() - 1);
    }
    None
}
