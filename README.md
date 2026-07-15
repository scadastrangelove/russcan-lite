# russcan-lite

*A Rust port of a C++ port of a research regex engine, trimmed to the parts a
firewall actually runs on every request. It's ports all the way down.*

**russcan-lite is the deployable literal-matching engine of the russcan port** —
a from-scratch Rust re-implementation of the
[Vectorscan](https://github.com/VectorCamp/vectorscan)/Hyperscan runtime,
specialised for **security matching**: the hot path of a WAF or IDS. Block mode,
floating literals, FDR + Teddy + confirm + the Rose literal interpreter, and
**no C anywhere in the data plane.**

> Pattern *compilation* stays upstream, in C `vectorscan`, offline — where a slow
> bug is merely a slow build. This crate only **loads** a serialized database and
> scans. The part that runs on every byte of every request is the part we rewrote.

## Why port a perfectly good C++ engine?

Because it is a perfectly good C++ engine.

A WAF exists so that hostile input never reaches a memory-unsafe parser. It is
therefore mildly awkward that the memory-unsafe parser is, traditionally, the
WAF: a C/C++ pattern matcher, in the hot path, on every byte of every request,
deciding whether the *next* thing is allowed to be dangerous.

The objection is not speed. C/C++ is not slow, and — see the table at the bottom
— neither are we; on realistic traffic the memory-safe engine is the faster one.
The objection is running a security control on "fast and *probably* correct."
russcan-lite moves the scanner into a language where the class of bug we worry
about most tends to show up as a compile error instead of a CVE.

## Scope — the engines a firewall actually uses

We did not port all of Hyperscan. We took a census of what real rulesets actually
compile to — **OWASP CRS v4** (`@rx`), **Suricata ET Open 7.0.3** (~7k PCRE plus
~50k `content` literals), and a production WAAP signature pack — and shipped the
engines that carry the *typical* signature, not the exotic tail. The production
pack, it turns out, compiles to an almost-pure-literal Rose program
(`CHECK_MED_LIT_NOCASE` + `REPORT` + `END`/`FINAL_REPORT`/`DEDUPE` are ~99% of the
instructions). So that is what this repo is.

**IN — the literal fast path (block mode, floating):**

- `russcan-simd` — the `V128` SIMD abstraction (SSSE3 / NEON / scalar backends).
- `russcan-bytecode` — serialized-DB reader + `RoseEngine` accessor (CRC-checked).
- `russcan-hwlm` — FDR + Teddy + noodle multi-literal matchers + the confirm path
  (with parse-time confirm-region validation — see *Security*).
- `russcan-rose` — the pure-**literal** `roseRunProgram_l` interpreter
  (`CHECK_BYTE` / `CHECK_MED_LIT` / `REPORT` / `DEDUPE` / `INCLUDED_JUMP` /
  `PUSH_DELAYED`), with fallible operand reads and an instruction budget.
- `russcan` — the `Database::load` + `scan_block` facade (FDR/Teddy dispatch,
  delayed-literal replay).

**OUT — lives only in the full russcan port:**

- The **Ф3 regex/NFA track** — LimEx / McClellan / Sheng / Castle / LBR. Real, but
  it is what the heavy CRS `@rx` patterns need, not the literal-dominated fast
  path this engine is for. In this repo `russcan-nfa` is a ~40-line **stub**: the
  literal interpreter compiles byte-for-byte unchanged, and a non-literal database
  is rejected with a clean `Unsupported` error instead of dragging in an engine we
  don't ship.
- **Gough, Tamarama, smallwrite** — never emitted once across CRS + Suricata + the
  production pack, so never ported (and asserted-out in the reader).
- Streaming, anchored matchers, the `libhs` FFI diff-oracle, `tools/`, `census/`,
  `fuzz/` — dev and research scaffolding.

The full port is the source of truth; russcan-lite is a curated, dependency-lean
subset. Changes flow full → lite by copy, which is precisely why the NFA stub
keeps `russcan-rose` textually identical rather than forked.

## Using it — embed the engine, feed it a database

russcan-lite does **not** compile patterns. It *loads* a serialized database and
scans. Two steps, and the split is the whole point: compilation is C, offline, at
build time; scanning is Rust, on every request.

**1 — Compile your patterns once, offline.** This is the only place C runs, and it
runs at build time, not on traffic. Use the pinned upstream
`vectorscan`/Hyperscan (`a1c107e`, 5.4.12) — the same `hs_compile_multi` +
`hs_serialize_database` the diff-oracle uses, so the bytes load byte-for-byte:

```c
// build-db.c — link against the pinned vectorscan. Run once; ship the output.
#include <hs/hs.h>
const char *pats[] = { "union select", "/etc/passwd", "foo|bar|baz" };
unsigned    ids[]  = { 101, 102, 103 };
unsigned    flg[]  = { 0, 0, 0 };
hs_database_t *db; hs_compile_error_t *e;
hs_compile_multi(pats, flg, ids, 3, HS_MODE_BLOCK, NULL, &db, &e);
char *bytes; size_t len;
hs_serialize_database(db, &bytes, &len);   // → write `bytes` to patterns.db
```

**2 — Embed the engine.** Add the facade crate and load the serialized bytes:

```toml
[dependencies]
russcan      = { git = "https://github.com/scadastrangelove/russcan-lite" }
russcan-hwlm = { git = "https://github.com/scadastrangelove/russcan-lite" }
```

```rust
use russcan::Database;
use russcan_hwlm::ScanCtl;

let blob = std::fs::read("patterns.db")?;   // the serialized DB from step 1
let db = Database::load(&blob)?;            // parse + validate (CRC + bounds)

db.scan_block(request_body, &mut |id: u32, to: u64| {
    // id = your pattern id (101 / 102 / …); to = end offset (last byte + 1)
    println!("rule {id} matched, ending at byte {to}");
    ScanCtl::Continue                        // return Terminate to stop early
})?;
```

That is the entire integration surface: `Database::load` + `scan_block` with a
closure. No global state, no C runtime, no allocation on the scan path.

### "…and feed it my own regexp?"

Yes — with one honest limit. Your patterns go through the *full* Hyperscan
compiler, so regex **syntax** is accepted; but russcan-lite only *runs* the
patterns that reduce to **literals**. A regex is fine here exactly when it isn't
really a regex.

| pattern | compiles to | russcan-lite |
|---|---|---|
| `union select`, `/etc/passwd`, `content:` strings | literal (FDR/Teddy) | ✅ runs |
| `foo\|bar\|baz`, fixed alternations | multi-literal | ✅ runs |
| `a.*b`, `\d{3,}`, char classes, backrefs | NFA (LimEx/McClellan/Sheng) | ❌ rejected |

A non-literal database is **rejected with a clean `Err`, never mis-scanned** — the
NFA stub returns `Unsupported` rather than guessing. If your ruleset is
literal-dominated (most WAF/IDS `content` signatures are), that's the whole job.
If you need real automaton evaluation in-engine, that's the full russcan port, not
this one.

## Correctness

Byte-for-byte, or it doesn't count.

- `cargo build` (dev + release) — clean, no warnings, stable Rust 1.86, zero C
  dependency; `cargo test` green.
- The `scan_db` diff-harness reproduces the C oracle's golden output
  **byte-for-byte on all 8 fixtures** (`basic`, `fdr400`, `fdrlit`, `realpack`,
  `t3_len7`, `t4_long`, `u1_len1`, `u2_len12`) — the acceptance gate.

```
cargo build --release
cargo test
target/release/scan_db <db> <corpus_hex> <out>   # == the C oracle, exactly
```

## Security — the gravity of a rewrite

Rewriting a security scanner in Rust does not delete its vulnerabilities. It
trades a *known* class of bugs — theirs, two decades catalogued — for an
*unknown* class: ours, written last week. Every new codebase has its own gravity,
and every rewrite is another black hole with its own event horizon of fresh CVEs
— a New Hop where you were promised A New Hope.

So russcan-lite is audited by its sibling,
**[rust-in-peace](https://github.com/scadastrangelove/rust-in-peace)** — a
Rust-security fork of Anthropic's defending-code reference harness (Miri UB /
sanitizer / panic / hang detectors). The literal engine went through its full
cycle: the memory-safety cluster is closed, and a **CRC-valid but hostile
database is rejected at parse time**, not read out of bounds in the hot path
(`crates/russcan/tests/hostile_db.rs` pins this). Integrity is not bounds
validation — a signature proves the bytes are intact, never that the offsets
inside them point where they claim. The scanner that guards your parsers gets a
guard of its own.

## Performance

Detection-specific workloads — real WAF-body scanning, not microbenchmarks.
Ratio is **literal-engine ÷ release Vectorscan** (higher = the Rust engine is
faster), 3× median on a shared box.

> Measured on the **full port's** literal scan path, not re-run in this repo: the
> bench bodies (`body256k`, `dense`, …) aren't shipped here, and the literal
> engine in russcan-lite is copied byte-identical from that port — the 8 golden
> fixtures above verify the copy produces identical output. The numbers transfer
> because the code is the same; they were not independently benchmarked on this
> checkout. Latest run 2026-07-15 (post-hardening), vs Release-Vectorscan.

| body | ratio | what it stresses |
|---|---:|---|
| clean (FP-saturated) | 0.88× | confirm-heavy worst case — many FDR candidates, zero literal matches |
| random | 1.01× | scan-heavy, parity |
| body256k (realistic) | ~1.10× | realistic WAF request body |
| dense (match-saturated) | ~1.09× | adversarial, match-heavy |

The single workload it loses is `clean` — a synthetic worst case engineered to
lose (all prefilter, no matches; against LLVM-built C the gap is <2%). On the two
bodies that resemble production traffic, the memory-safe engine is the faster
one. This surprises people. It stopped surprising the port's authors somewhere
around the fourth optimisation stage — the full 0.53× → parity-with-a-win journey
is documented in the full port's `PERF_METHODOLOGY.md`.

## Contact

**Sergey Gordeychik**

- Email: [scadastrangelove@gmail.com](mailto:scadastrangelove@gmail.com)
- X/Twitter: [@scadasl](https://x.com/scadasl)
- Blog: [scadastrangelove.blogspot.com](https://scadastrangelove.blogspot.com/)

## License / provenance

Derived from the russcan port, which ports upstream
[`vectorscan`](https://github.com/VectorCamp/vectorscan) (pinned `a1c107e`,
5.4.12; Apache-2.0 / BSD-3-Clause). See the full port for pinned-upstream
provenance.
