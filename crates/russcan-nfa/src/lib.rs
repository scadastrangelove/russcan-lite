//! russcan-lite **stub** of `russcan-nfa`.
//!
//! The full NFA/regex engine (Ф3: LimEx / McClellan / Sheng / Castle / LBR)
//! lives only in the full russcan port. russcan-lite is literal-only: a
//! pure-literal Rose program never emits the leftfix/infix opcodes
//! (`CHECK_PREFIX` / `CHECK_INFIX`) that call into it. This stub exists so the
//! literal interpreter (`russcan-rose`) compiles byte-for-byte unchanged; its
//! constructors return `Unsupported`, so a non-literal DB fails gracefully
//! (a clean error, never a mis-scan) instead of pulling in the whole Ф3 track.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NfaError {
    Truncated,
    BadTable(&'static str),
    Unsupported(&'static str),
}
impl core::fmt::Display for NfaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NfaError::Truncated => write!(f, "байткод NFA обрезан"),
            NfaError::BadTable(w) => write!(f, "битая таблица NFA: {w}"),
            NfaError::Unsupported(w) => write!(f, "вне russcan-lite: {w}"),
        }
    }
}
impl std::error::Error for NfaError {}

pub mod dispatch {
    use super::NfaError;

    /// Stub leftfix/infix NFA. Never successfully constructed in russcan-lite.
    pub struct Nfa<'a>(core::marker::PhantomData<&'a [u8]>);

    impl<'a> Nfa<'a> {
        pub fn from_bytes(_nfa: &'a [u8]) -> Result<Nfa<'a>, NfaError> {
            Err(NfaError::Unsupported("NFA/regex (Ф3) не входит в russcan-lite"))
        }
        pub fn in_accept_state(&self, _input: &[u8], _report: u32) -> Result<bool, NfaError> {
            Err(NfaError::Unsupported("NFA/regex (Ф3) не входит в russcan-lite"))
        }
    }
}
