//! panic_fuzz — Stage-1 blind panic-fuzzer for russcan.
//!
//! Methodology: rust-in-peace `profiles/rust/fuzzing.md` (the cheapest rung —
//! stable Rust, no nightly/coverage/sanitizer). Throws mutated bytes at the two
//! public surfaces inside `catch_unwind` and reports any input that unwinds.
//!
//! Domain-specific by design (corpus = threat model): seeds are the real `.db`
//! fixtures and `.corpus` bodies; mutations smash header fields / offsets /
//! counts (the crafted-DB "integrity != bounds" surface) and length edges.
//! `catch_unwind` here is the fuzzer's *detector*, not a production shield.
//!
//! usage: panic_fuzz <fixtures_dir> [iters] [seed]
//! Exit 0 = clean; exit 1 + `crash-*.bin` written = a panic was caught.

use russcan::Database;
use russcan_hwlm::ScanCtl;
use std::fs;
use std::panic::{self, AssertUnwindSafe};

/// Deterministic splitmix64 — reproducible runs, no OS entropy (a crash input is
/// replayable from the printed seed).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// Structural mutation, not just bit-flips: length edges (truncate/extend) and
/// u32 field-smash in the first 512 bytes — the serialized-DB header (magic /
/// version / size / offsets / counts) is where crafted-DB bugs concentrate.
fn mutate(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(6) {
        match rng.below(6) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            1 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = rng.next() as u8;
            }
            2 => {
                let n = rng.below(b.len().max(1));
                b.truncate(n); // length edge (the F-101 class: guard vs actual read)
            }
            3 => {
                for _ in 0..rng.below(64) {
                    b.push(rng.next() as u8);
                }
            }
            4 if b.len() >= 4 => {
                // hostile u32 at a header offset: huge offset/count / 0 / len+slop
                let hi = b.len().saturating_sub(3).min(512).max(1);
                let off = rng.below(hi);
                let choices = [0xffff_ffffu32, 0x7fff_fff0, 0, 1, b.len() as u32 + 4096];
                let v = choices[rng.below(choices.len())];
                b[off..off + 4].copy_from_slice(&v.to_le_bytes());
            }
            _ if b.len() >= 2 => {
                let (a, c) = (rng.below(b.len()), rng.below(b.len()));
                let piece = b[a.min(c)..a.max(c)].to_vec();
                let at = rng.below(b.len());
                b.splice(at..at, piece);
            }
            _ => {}
        }
    }
    b
}

fn load_dir(dir: &str, ext: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some(ext) {
                if let Ok(b) = fs::read(&p) {
                    out.push(b);
                }
            }
        }
    }
    out
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dir = a.get(1).cloned().unwrap_or_else(|| "fixtures".into());
    let iters: u64 = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(2_000_000);
    let seed: u64 = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(0x00C0_FFEE);

    let all_db = load_dir(&dir, "db");
    let corpus_seeds = load_dir(&dir, "corpus");
    if all_db.is_empty() {
        eprintln!("no *.db seeds in {dir}");
        std::process::exit(2);
    }
    // A valid DB (any size) kept alive for the scan-surface fuzzing.
    let valid = all_db
        .iter()
        .find(|b| Database::load(b).is_ok())
        .cloned()
        .expect("at least one fixture must load");
    let valid_db = Database::load(&valid).unwrap();
    // Mutation seeds: cap size — a small fixture carries the full header/offset
    // structure, and re-CRC'ing megabyte blobs per iter just burns throughput.
    let db_seeds: Vec<Vec<u8>> = all_db.into_iter().filter(|b| b.len() <= 16 * 1024).collect();
    let db_seeds = if db_seeds.is_empty() { vec![valid.clone()] } else { db_seeds };

    eprintln!(
        "panic_fuzz: {} db-seeds, {} corpus-seeds, {iters} iters, seed={seed:#x}",
        db_seeds.len(),
        corpus_seeds.len()
    );
    let mut rng = Rng(seed);
    let mut crashes = 0u64;

    for i in 0..iters {
        // Surface A — DB parse (operator-controlled → latent; crafted-DB class).
        let m = mutate(&db_seeds[rng.below(db_seeds.len())], &mut rng);
        if panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = Database::load(&m);
        }))
        .is_err()
        {
            let name = format!("crash-load-{crashes}.bin");
            let _ = fs::write(&name, &m);
            eprintln!("CRASH #{crashes} [load] {} bytes -> {name}", m.len());
            crashes += 1;
        }

        // Surface B — scan buffer (attacker-controlled → live surface).
        let sb: Vec<u8> = if !corpus_seeds.is_empty() && rng.below(2) == 0 {
            mutate(&corpus_seeds[rng.below(corpus_seeds.len())], &mut rng)
        } else {
            (0..rng.below(300)).map(|_| rng.next() as u8).collect()
        };
        if panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = valid_db.scan_block(&sb, &mut |_, _| ScanCtl::Continue);
        }))
        .is_err()
        {
            let name = format!("crash-scan-{crashes}.bin");
            let _ = fs::write(&name, &sb);
            eprintln!("CRASH #{crashes} [scan] {} bytes -> {name}", sb.len());
            crashes += 1;
        }

        if i > 0 && i % 500_000 == 0 {
            eprintln!("  {i} iters, {crashes} crashes");
        }
    }

    eprintln!("done: {iters} iters x 2 surfaces, {crashes} crashes");
    std::process::exit(if crashes == 0 { 0 } else { 1 });
}
