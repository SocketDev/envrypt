#!/usr/bin/env bash
# WP-21 fuzz runner (doc 11 §7). Single source of truth for the per-target
# libFuzzer flags so local acceptance runs and the nightly CI job match exactly.
#
#   fuzz/run.sh <target> [max_total_time_seconds]   # default 600 = 10 min/target
#   fuzz/run.sh all       [max_total_time_seconds]   # each target in turn
#
# Requires a nightly toolchain (cargo-fuzz sets the sanitizer flags + `--cfg
# fuzzing`). Invoked via `cargo +nightly fuzz run` when cargo is the rustup shim,
# or `rustup run nightly cargo fuzz run` otherwise (both handled below).
set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DICT="$FUZZ_DIR/fuzz.dict"
DURATION="${2:-600}"

# Per-target libFuzzer flags. doc 11 §7.3 specifies `-timeout=1 -rss_limit_mb=512`;
# both are calibrated up here for the ASan + coverage instrumentation cargo-fuzz
# builds with:
#   * `-timeout=10` — absorbs the ~10x ASan slowdown (a genuine hang is unbounded
#     and still caught). The D-05 growing-string expand class (O(cap²) work that
#     would trip ANY finite timeout at the production 10k cap) is neutralized in
#     `parse_pipeline` by the `cfg(fuzzing)` lowered expand cap in envrypt
#     (`MAX_EXPAND_ITERATIONS`), NOT by a timeout hack.
#   * `-rss_limit_mb=2048` — ASan shadow memory + libFuzzer's accumulating coverage
#     counters/corpus push the *baseline* RSS of the scan/IndexMap-touching targets
#     past 512 MB over a long run (measured ~410-527 MB) with NO per-exec allocation
#     blowup (the offending 14-byte "oom" input reproduces in 41 ms flat). A real
#     unbounded allocation still trips 2048.
#   * `-max_len` bounds a single .env-sized input.
# See docs/envrypt/fuzzing.md.
target_flags() {
  case "$1" in
    parse_pipeline)   echo "-timeout=10 -rss_limit_mb=2048 -max_len=4096" ;;
    ecies_decrypt)    echo "-timeout=10 -rss_limit_mb=2048" ;;
    upsert_roundtrip) echo "-timeout=10 -rss_limit_mb=2048 -max_len=4096" ;;
    sockeye_decode)   echo "-timeout=10 -rss_limit_mb=2048 -max_len=256" ;;
    *) echo "unknown target: $1" >&2; return 1 ;;
  esac
}

# Pick the invocation that handles `+nightly` in this environment.
run_fuzz() {
  if cargo +nightly --version >/dev/null 2>&1; then
    cargo +nightly fuzz "$@"
  else
    rustup run nightly cargo fuzz "$@"
  fi
}

run_one() {
  local t="$1"
  echo "===== fuzz: $t (max_total_time=${DURATION}s) ====="
  # shellcheck disable=SC2046
  run_fuzz run --target x86_64-unknown-linux-gnu "$t" -- \
    -max_total_time="$DURATION" -dict="$DICT" -print_final_stats=1 \
    $(target_flags "$t")
}

case "${1:-all}" in
  all)
    for t in parse_pipeline ecies_decrypt upsert_roundtrip sockeye_decode; do run_one "$t"; done ;;
  parse_pipeline|ecies_decrypt|upsert_roundtrip|sockeye_decode)
    run_one "$1" ;;
  *)
    echo "usage: $0 <parse_pipeline|ecies_decrypt|upsert_roundtrip|sockeye_decode|all> [seconds]" >&2
    exit 2 ;;
esac
