//! Rose runtime (Ф4): интерпретатор rose-программ, scratch, catch-up.
//!
//! Референс: `vectorscan/src/rose/`.
//!
//! FDR-only срез (Ф2-lite): реализован литеральный интерпретатор
//! (`roseRunProgram_l`) — см. [`literal`]. NFA/anchored/catch-up — позже.

pub mod literal;

pub use literal::{run_program, Dedupe, InterpError};
