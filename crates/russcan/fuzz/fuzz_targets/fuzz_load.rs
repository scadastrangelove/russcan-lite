//! Stage-3 coverage-guided fuzz target: the serialized-DB parser
//! (`Database::load`) — the crafted-DB "integrity != bounds" surface where the
//! whole hardened finding class lives. The fuzz input IS the DB bytes.
//! Seed corpus: the real `.db` fixtures (see fuzz/corpus/fuzz_load/).
#![no_main]

use libfuzzer_sys::fuzz_target;
use russcan::Database;

fuzz_target!(|data: &[u8]| {
    // A hostile/malformed DB must fail gracefully (clean Err), never panic/OOB/hang.
    let _ = Database::load(data);
});
