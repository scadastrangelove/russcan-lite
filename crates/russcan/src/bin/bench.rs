//! bench — throughput скана russcan: загружает БД, сканирует тело N раз,
//! считает матчи (защита от dead-code), печатает MB/s. Контракт совпадает с
//! `lit_oracle bench` (то же тело, те же итерации) для честного сравнения.
//!
//! usage: bench <db> <body_file> [iters]

use russcan::Database;
use russcan_hwlm::ScanCtl;
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: bench <db> <body_file> [iters]");
        std::process::exit(2);
    }
    let iters: u32 = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let blob = std::fs::read(&a[1]).expect("read db");
    let body = std::fs::read(&a[2]).expect("read body");
    let db = Database::load(&blob).unwrap_or_else(|e| panic!("load db: {e}"));

    let mut matches: u64 = 0;
    // warmup
    db.scan_block(&body, &mut |_, _| {
        matches += 1;
        ScanCtl::Continue
    })
    .unwrap();
    matches = 0;

    let t0 = Instant::now();
    for _ in 0..iters {
        db.scan_block(&body, &mut |_, _| {
            matches += 1;
            ScanCtl::Continue
        })
        .unwrap();
    }
    let dt = t0.elapsed().as_secs_f64();
    let mb = body.len() as f64 * iters as f64 / (1024.0 * 1024.0);
    eprintln!(
        "russcan: {}-byte body x{} = {:.1} MB in {:.4} s = {:.1} MB/s ({} matches)",
        body.len(),
        iters,
        mb,
        dt,
        mb / dt,
        matches
    );
    println!("{:.1}", mb / dt);
}
