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
  Castle / LBR). Not needed for literal matching.
- **Leftfix / prefix** opcodes (`CHECK_PREFIX` → NFA) — feature-gated OFF in the
  lite build (pure-literal programs never emit them). This is the one coupling
  to resolve during extraction: `russcan-rose` currently pulls `russcan-nfa` for
  leftfix; the lite build gates that behind a `leftfix` cargo feature so the
  literal path builds with no NFA dependency.
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

Repo initialized (scaffold). Next: extract the five literal-path crates from the
full port with the `leftfix` feature gate, wire the minimal workspace, and carry
over the literal diff-tests (bit-exact vs the C oracle) as the acceptance gate.

## License / provenance

Derived from the russcan port (which ports upstream `vectorscan`, Apache-2.0 /
BSD). See the full port for pinned-upstream provenance (`a1c107e`, 5.4.12).
