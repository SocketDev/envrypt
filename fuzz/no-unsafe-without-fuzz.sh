#!/usr/bin/env bash
# Grep-level lint: every `unsafe` in envrypt that SHIPS must carry a
# `// FUZZ: <target>` annotation naming the fuzz target that covers the path, so
# no shipped `unsafe` lacks a fuzz target exercising it. The annotation appears
# on the same line as the `unsafe` token or within the 3 preceding lines. See
# docs/envrypt/fuzzing.md.
#
# `#[cfg(test)]` code is EXEMPT: test modules/functions are compiled out of the
# release build, so their `unsafe` never ships and the "no unsafe ships" rule
# does not apply to them. The exemption is scoped precisely to `#[cfg(test)]`
# regions (module or fn, tracked by brace depth) — all other (production) code
# stays strictly gated.
#
# Exit 0 = clean (every shipped `unsafe` carries a `// FUZZ:` annotation).
# Exit 1 lists every unannotated shipped `unsafe`. Run from anywhere.
#
# Scans `crates/envrypt/src`; comment-only lines are skipped so a doc-comment
# mention of the word "unsafe" is not a false offender.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/crates/envrypt/src"

# Emit "start,end" (1-based, inclusive) line ranges for every `#[cfg(test)]` item
# (module or fn) in a file, via brace-depth tracking. Double-quoted strings and
# line comments are stripped first so braces inside them do not skew the count.
compute_test_ranges() {
  awk '
    {
      code = $0
      gsub(/"([^"\\]|\\.)*"/, "", code)   # drop double-quoted strings
      sub(/\/\/.*/, "", code)             # drop line comments
      tmp = code; opens  = gsub(/\{/, "x", tmp)
      tmp = code; closes = gsub(/\}/, "x", tmp)
      if (intest) {
        depth += opens - closes
        if (depth <= 0) { print start "," NR; intest = 0; pending = 0 }
        next
      }
      if (pending && opens > 0) {
        intest = 1; start = pendline; depth = opens - closes; pending = 0
        if (depth <= 0) { print start "," NR; intest = 0 }
        next
      }
      if (code ~ /#\[cfg\((all\()?test[,)]/) {
        pending = 1; pendline = NR
        if (opens > 0) {   # attribute and opening brace on one line
          intest = 1; start = NR; depth = opens - closes; pending = 0
          if (depth <= 0) { print start "," NR; intest = 0 }
        }
      }
    }
    END { if (intest) print start "," NR }
  ' "$1"
}

offenders=0
# Ranges of the file currently being scanned. `grep -rn` groups every match for a
# file contiguously and never revisits a file, so recomputing on file change is
# sufficient (and stays bash 3.2 compatible — no associative arrays).
cur_file=""
cur_ranges=""
# `-n` line numbers, word-boundary `unsafe`; skip if none.
while IFS= read -r hit; do
  [ -n "$hit" ] || continue
  file="${hit%%:*}"
  rest="${hit#*:}"
  line="${rest%%:*}"
  content="${rest#*:}"
  # Skip comment-only lines: a real `unsafe` block is never a `//`-led line, so the
  # only such matches are doc-comment word mentions (e.g. "set_var becomes `unsafe`").
  case "${content#"${content%%[![:space:]]*}"}" in
  //*) continue ;;
  esac
  # Refresh the test-range set when the scan moves to a new file.
  if [ "$file" != "$cur_file" ]; then
    cur_file="$file"
    cur_ranges="$(compute_test_ranges "$file")"
  fi
  # Skip `unsafe` inside a `#[cfg(test)]` region — test code never ships.
  in_test=0
  while IFS=, read -r rstart rend; do
    [ -n "$rstart" ] || continue
    if [ "$line" -ge "$rstart" ] && [ "$line" -le "$rend" ]; then
      in_test=1
      break
    fi
  done <<< "$cur_ranges"
  [ "$in_test" -eq 1 ] && continue
  start=$((line > 3 ? line - 3 : 1))
  # The annotation may be on the unsafe line or up to 3 lines above it.
  if sed -n "${start},${line}p" "$file" | grep -q '// FUZZ:'; then
    continue
  fi
  echo "::error file=${file#"$ROOT"/},line=${line}::unsafe without a '// FUZZ: <target>' annotation (see docs/envrypt/fuzzing.md)"
  offenders=$((offenders + 1))
done < <(grep -rn --include='*.rs' -E '(^|[^A-Za-z_])unsafe([^A-Za-z_]|$)' "$SRC" 2>/dev/null || true)

if [ "$offenders" -gt 0 ]; then
  echo "no-unsafe-without-fuzz: $offenders unannotated unsafe block(s) in envrypt" >&2
  exit 1
fi
echo "no-unsafe-without-fuzz: OK (every envrypt unsafe carries a // FUZZ: annotation)"
