# russcan-lite

**The lean literal-matcher build of [russcan](../russcan).** A block-mode,
pure-literal multi-pattern scanner — FDR + Teddy + confirm + the Rose literal
interpreter — with **zero C dependency**. This is the deployable engine
(the piece meant to replace `libhs.so` in the WAAP data plane), kept in its own
repo so it isn't confused with the full Vectorscan→Rust research port.

> Compilation of patterns stays with upstream C `vectorscan` (offline). This
> engine only **loads** a serialized DB and scans — no C code in the data plane.

## Scope — what's IN

The literal floating path, block mode:

- `russcan-simd` — the `V128` SIMD abstraction (SSSE3 / NEON / scalar backends).
- `russcan-bytecode` — serialized-DB reader + `RoseEngine` accessor (CRC-checked).
- `russcan-hwlm` — FDR + Teddy + noodle literal matchers, confirm path (with the
  parse-time confirm-region validation hardening).
- `russcan-rose` — the pure-literal `roseRunProgram_l` interpreter
  (CHECK_BYTE / CHECK_MED_LIT / REPORT / DEDUPE / INCLUDED_JUMP / PUSH_DELAYED),
  with fallible operand reads + an instruction budget.
- `russcan` — the `Database::load` + `scan_block` facade (FDR/Teddy dispatch,
  delayed-literal replay).

## Scope — what's OUT (lives only in the full port)

- **`russcan-nfa`** — the Ф3 regex research track (LimEx / McClellan / Sheng /
  Castle / LBR). Not needed for literal matching. In this repo it is replaced by
  a ~40-line **stub crate** (`crates/russcan-nfa`) so the literal interpreter
  compiles byte-for-byte unchanged: its constructors return `Unsupported`, so a
  non-literal DB fails with a clean error instead of pulling in the whole engine.
- **Leftfix / prefix / infix** opcodes (`CHECK_PREFIX` / `CHECK_INFIX` → NFA) —
  never emitted by a pure-literal Rose program, so they are never reached. The
  stub keeps `russcan-rose` identical to the full port (zero source divergence),
  which is what lets changes flow full → lite by copy rather than by re-patching.
- `oracle` (libhs FFI diff-test shim), `tools/`, `census/`, `fuzz/`,
  `mvp-ffi-baseline/` — dev/research scaffolding.
- Streaming, anchored, and non-FDR floating matchers — out of scope by design.

## Relation to the full port

| | full [`russcan`](../russcan) | `russcan-lite` (this repo) |
|---|---|---|
| purpose | complete Vectorscan→Rust port (research) | deployable literal engine |
| crates | + `russcan-nfa`, `oracle`, tools, census | literal path only |
| regex/NFA | yes (Ф3) | no |
| C dependency | oracle (test-only) | **none** |
| target | parity with all of hs | replace `libhs.so` in the WAAP data plane |

The full port is the source of truth; russcan-lite is a curated, dependency-lean
subset of it. Changes flow full → lite.

## Status

**Working.** The six-crate workspace (five literal-path crates + the NFA stub)
builds clean on stable Rust (`cargo build`, dev + release, no warnings) with zero
C dependency. `cargo test` is green, and the literal diff-harness (`scan_db`)
reproduces the C oracle's golden output **byte-for-byte on all 8 fixtures**
(`basic`, `fdr400`, `fdrlit`, `realpack`, `t3_len7`, `t4_long`, `u1_len1`,
`u2_len12`) — the acceptance gate for the extraction.

```
cargo build --release
cargo test
# end-to-end vs golden:
target/release/scan_db <db> <corpus_hex> <out>   # matches the C oracle exactly
```

The hostile-DB regression tests (`crates/russcan/tests/hostile_db.rs`) also carry
over: a CRC-valid but confirm-corrupted DB is rejected at parse time, not read
out of bounds in the hot path.

## License / provenance

Derived from the russcan port (which ports upstream `vectorscan`, Apache-2.0 /
BSD). See the full port for pinned-upstream provenance (`a1c107e`, 5.4.12).
