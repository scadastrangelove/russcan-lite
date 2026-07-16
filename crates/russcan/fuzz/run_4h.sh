#!/usr/bin/env bash
# cargo-fuzz 4h run of both russcan surfaces in parallel. Run inside the nightly
# container from crates/russcan/fuzz/. Logs + any crash artifacts land here.
set -u
SECS=${1:-14400}   # 4h
cd "$(dirname "$0")"
export CARGO_TERM_COLOR=never
echo "=== cargo fuzz: fuzz_load + fuzz_scan, ${SECS}s each, $(date -u) ==="
cargo fuzz run fuzz_load -- -max_total_time=$SECS -print_final_stats=1 \
    > load.log 2>&1 &
PL=$!
cargo fuzz run fuzz_scan -- -max_total_time=$SECS -print_final_stats=1 \
    > scan.log 2>&1 &
PS=$!
wait $PL; echo "fuzz_load exit=$?"
wait $PS; echo "fuzz_scan exit=$?"
echo "=== done $(date -u) ==="
echo "--- load tail ---"; tail -12 load.log
echo "--- scan tail ---"; tail -12 scan.log
ls -la artifacts/*/ 2>/dev/null && echo "!!! ARTIFACTS (crashes)" || echo "no crash artifacts"
