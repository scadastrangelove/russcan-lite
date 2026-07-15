//! Наивные скалярные реализации accel-предикатов: определение семантики.
//!
//! Используются как slow-путь для буферов < 16 байт (эквивалент C-шных
//! `shuftiFwdSlow`/maskz-блоков) и как ground truth в property-тестах.

/// Байт принадлежит shufti-классу.
#[inline(always)]
pub fn shufti_in_class(lo: &[u8; 16], hi: &[u8; 16], b: u8) -> bool {
    lo[(b & 0xf) as usize] & hi[(b >> 4) as usize] != 0
}

/// Байт принадлежит truffle-классу.
#[inline(always)]
pub fn truffle_in_class(clear: &[u8; 16], set: &[u8; 16], b: u8) -> bool {
    let m = if b < 0x80 { clear } else { set };
    m[(b & 0xf) as usize] & (1u8 << ((b >> 4) & 7)) != 0
}

#[inline(always)]
fn verm_matches(c: u8, nocase: bool, b: u8) -> bool {
    let cm = if nocase { 0xdf } else { 0xff };
    b & cm == c & cm
}

pub fn shufti_fwd(lo: &[u8; 16], hi: &[u8; 16], buf: &[u8]) -> Option<usize> {
    buf.iter().position(|&b| shufti_in_class(lo, hi, b))
}

pub fn shufti_rev(lo: &[u8; 16], hi: &[u8; 16], buf: &[u8]) -> Option<usize> {
    buf.iter().rposition(|&b| shufti_in_class(lo, hi, b))
}

pub fn truffle_fwd(clear: &[u8; 16], set: &[u8; 16], buf: &[u8]) -> Option<usize> {
    buf.iter().position(|&b| truffle_in_class(clear, set, b))
}

pub fn truffle_rev(clear: &[u8; 16], set: &[u8; 16], buf: &[u8]) -> Option<usize> {
    buf.iter().rposition(|&b| truffle_in_class(clear, set, b))
}

pub fn verm_fwd(c: u8, nocase: bool, buf: &[u8]) -> Option<usize> {
    buf.iter().position(|&b| verm_matches(c, nocase, b))
}

pub fn nverm_fwd(c: u8, nocase: bool, buf: &[u8]) -> Option<usize> {
    buf.iter().position(|&b| !verm_matches(c, nocase, b))
}

pub fn verm_rev(c: u8, nocase: bool, buf: &[u8]) -> Option<usize> {
    buf.iter().rposition(|&b| verm_matches(c, nocase, b))
}

pub fn nverm_rev(c: u8, nocase: bool, buf: &[u8]) -> Option<usize> {
    buf.iter().rposition(|&b| !verm_matches(c, nocase, b))
}
