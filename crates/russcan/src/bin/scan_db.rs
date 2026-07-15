//! scan_db — end-to-end дифф-харнесс: читает сериализованную БД + hex-корпус,
//! печатает матчи в формате golden оракула `recIdx: id@to id@to ...`
//! (сортировка по (to,id)) для побайтового сравнения с `lit_oracle scan`.
//!
//! usage: scan_db <db> <corpus_hex> <out>

use russcan::Database;
use russcan_hwlm::ScanCtl;
use std::fs;
use std::io::Write;

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 4 {
        eprintln!("usage: scan_db <db> <corpus_hex> <out>");
        std::process::exit(2);
    }
    let blob = fs::read(&a[1]).expect("read db");
    let db = Database::load(&blob).unwrap_or_else(|e| panic!("load db: {e}"));

    let corpus = fs::read_to_string(&a[2]).expect("read corpus");
    let mut out = fs::File::create(&a[3]).expect("create out");

    for (idx, line) in corpus.lines().enumerate() {
        let data = unhex(line).unwrap_or_default();
        let mut hits: Vec<(u64, u32)> = Vec::new();
        db.scan_block(&data, &mut |id, to| {
            hits.push((to, id));
            ScanCtl::Continue
        })
        .unwrap_or_else(|e| panic!("scan rec {idx}: {e}"));
        hits.sort_unstable();
        write!(out, "{idx}:").unwrap();
        for (to, id) in &hits {
            write!(out, " {id}@{to}").unwrap();
        }
        writeln!(out).unwrap();
    }
}
