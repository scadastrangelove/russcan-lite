//! Stage-3 coverage-guided fuzz target: the scan surface (`scan_block`) — the
//! ATTACKER-controlled bytes (a WAF/IDS request body). The DB is a fixed valid
//! fixture; the fuzz input is the scanned buffer.
//! Seed corpus: real bodies (see fuzz/corpus/fuzz_scan/).
#![no_main]

use libfuzzer_sys::fuzz_target;
use russcan::Database;
use russcan_hwlm::ScanCtl;
use std::sync::OnceLock;

static DB_BYTES: &[u8] = include_bytes!("../../tests/fixtures/realpack.db");

fn db() -> &'static Database<'static> {
    static DB: OnceLock<Database<'static>> = OnceLock::new();
    DB.get_or_init(|| Database::load(DB_BYTES).expect("realpack fixture must load"))
}

fuzz_target!(|data: &[u8]| {
    // No attacker buffer may panic/OOB/hang the scanner.
    let _ = db().scan_block(data, &mut |_, _| ScanCtl::Continue);
});
