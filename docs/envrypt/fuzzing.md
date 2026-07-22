# Fuzzing envrypt

How the `fuzz/` workspace works, the rules CI enforces around it, and the
standing performance priors for the library. CI: `.github/workflows/rust-fuzz.yml`
(build gate on every push, nightly coverage-guided runs).

## The `unsafe` rule — every `unsafe` needs a `// FUZZ:` annotation

The release profile sets `panic = "abort"`, so unguarded undefined behavior is a
hard crash for consumers. Rule: any `unsafe` token in `crates/envrypt/src/**`
that ships must carry a `// FUZZ: <target>` comment on the same line or within
the 3 lines above it, naming the fuzz target that exercises the path.

- Lint: `bash fuzz/no-unsafe-without-fuzz.sh`, run in the `rust-fuzz.yml`
  `build` job.
- **`#[cfg(test)]` code is exempt.** Test modules and functions are compiled out
  of the release build, so their `unsafe` never ships and the "no unsafe ships"
  rule does not apply. The lint scopes the exemption precisely to `#[cfg(test)]`
  regions (module or fn, tracked by brace depth); every other line stays gated.
  Example: `sockeye`'s child-process test harness uses raw `libc::{pipe, fork,
dup2, waitpid, …}` calls under `#[cfg(test)]` — those are exempt, while the
  production `from_raw_fd` below is annotated.
- The one shipped `unsafe` is `sockeye::read_pipe`'s
  `File::from_raw_fd(3)` — taking ownership of the inherited Sockeye descriptor.
  It is annotated `// FUZZ: sockeye_decode`: the `sockeye_decode` target fuzzes
  the record parser that descriptor feeds (`sockeye::decode` over raw bytes),
  which is the whole surface an untrusted parent controls.
- Adding more `unsafe`? Add (or extend) a fuzz target that drives the exact
  path, then the annotation. Byte-reinterpretation goes through `zerocopy`
  (`TryFromBytes` at trust boundaries), never a raw transmute.

## Layout

`fuzz/` is a standalone cargo workspace (its own empty `[workspace]` table; the
parent workspace lists `exclude = ["fuzz"]`), so a repo-root `cargo build`/`test`
never sweeps it in and it never inherits the ship `[profile.release]`. Its
profile inverts the ship profile — `debug-assertions = true`,
`overflow-checks = true`, `debug = 1` — so assertion violations and silent wraps
become crash findings. Targets link `envrypt` with default features only, the
same minimal graph the shipped parse path uses.

Files:

- `fuzz/fuzz_targets/{parse_pipeline,ecies_decrypt,upsert_roundtrip,sockeye_decode}.rs`
  — the targets.
- `fuzz/fuzz.dict` — libFuzzer dictionary: `.env` grammar tokens, the
  `encrypted:` prefix, key-naming conventions, the UTF-16LE/UTF-8 BOMs, and the
  internal upsert placeholder sentinel (`crates/envrypt/src/edit.rs`).
- `fuzz/corpus/<target>/` — the committed seed corpus.
- `fuzz/seed-corpus.py` — regenerates the seed corpus from the 88 spec inputs
  (`conformance/cases/spec/spec.json`), the fixture trees
  (`conformance/fixtures/**`), and crafted per-target edge seeds. Seed files use
  neutral names (never `.env*`) so the repo `.gitignore` keeps them. Default
  mode RESETS each corpus dir to exactly the seed set (the committed corpus is
  deterministic); `--additive` layers the seeds on top of an existing corpus —
  the nightly CI job uses `--additive` after restoring its cached,
  coverage-guided corpus so growth accumulates across nights (a reset would wipe
  the restored growth before every run).
- `fuzz/run.sh` — the single source of truth for per-target libFuzzer flags,
  used by both local runs and the nightly CI job.
- `fuzz/no-unsafe-without-fuzz.sh` — the lint above.

**Keep `fuzz/Cargo.lock` fresh.** The lock pins the full `envrypt` dependency
graph, so any change that adds or bumps an `envrypt` dependency must refresh it
in the same change: run a resolve against the fuzz manifest —
`cargo tree --manifest-path fuzz/Cargo.toml` (or `cargo +nightly fuzz build`) —
then commit the updated `fuzz/Cargo.lock`. The `rust-fuzz.yml` build job runs
`cargo metadata --manifest-path fuzz/Cargo.toml --locked` and FAILS on a stale
lock (otherwise a `cargo fuzz build` silently rewrites the lock at build time,
breaking reproducibility).

## Running

Requires a nightly toolchain (cargo-fuzz sets the sanitizer flags plus the
build-wide `--cfg fuzzing`). Install once: `cargo install cargo-fuzz`.

```sh
python3 fuzz/seed-corpus.py            # (re)generate the seed corpus
cargo +nightly fuzz build              # build all four targets
fuzz/run.sh all 600                    # 10 min/target with the canonical flags
fuzz/run.sh parse_pipeline 60          # one target, 60 s
```

If your `cargo` is not the rustup shim, `fuzz/run.sh` falls back to
`rustup run nightly cargo fuzz …` automatically.

## The two `cfg(fuzzing)` harness seams (production is unchanged)

cargo-fuzz sets `--cfg fuzzing` build-wide. Two `envrypt` code paths compile
differently ONLY under that cfg (declared in `crates/envrypt/Cargo.toml`'s
`check-cfg`). No default, normal, or `--all-features` build ever sets it, so
shipped behavior and `cargo test` behavior are byte-for-byte the production
code.

1. **`parse::evaluate` command-substitution stub.** Fuzz bytes must NEVER be
   executed by a shell. Under `--cfg fuzzing`, `exec_shell` is a deterministic
   pure stub that echoes the command text back — the real `EVAL_RE` match +
   `chomp` + replace machinery is still fuzzed, but nothing spawns. The
   `parse_pipeline` target additionally `compile_error!`s under `not(fuzzing)`
   so it can never be built without the stub.
2. **`parse::expand` lowered iteration cap + output-size guard.** A
   self-reinserting expansion (a `${…}`/`$'`/`$&` value that re-inserts itself)
   has two hostile members. The ADDITIVE member grows the result about linearly
   per pass and does O(cap²) work: at the production
   `MAX_EXPAND_ITERATIONS = 10_000` a single exec runs for tens of seconds even
   on a ≤128-byte input (measured 35 s uninstrumented; minutes under ASan),
   tripping every finite `-timeout`. Under `--cfg fuzzing` the cap is 256, so
   the identical scan → look-up → replace path is fuzzed on grown strings fast.
   The MULTIPLICATIVE member (an after-match/whole-match reinsertion that
   duplicates a still-`${…}`-bearing tail) grows the result exponentially per
   pass and OOM-aborts the fuzzer at ~31 passes regardless of any iteration cap
   (a past run recorded a 2.4 GB single allocation). So under `--cfg fuzzing` a
   companion output-size guard, `parse::expand::FUZZ_MAX_EXPAND_OUTPUT_BYTES`
   (16 KiB), truncates and breaks once the intermediate result exceeds the
   budget. Production keeps the 10 000 cap and unbounded output — that envelope
   is deliberate, documented behavior of the frozen expansion semantics.

The `ecies_decrypt` target also uses a `cfg(fuzzing)`
`crypto::fuzz_decrypt_wire_payload` entry to drive decryption over raw
post-base64 bytes (the public `decrypt` entry only reaches byte sequences a
lenient base64 decoder can produce).

## Per-target flags (in `fuzz/run.sh`)

Calibrated for the ASan + coverage instrumentation of a cargo-fuzz build:

- `-timeout=10` — absorbs the ~10x ASan slowdown; a genuine hang is unbounded
  and still caught. (The slow expansion class is handled by the `cfg(fuzzing)`
  cap above, never by a timeout hack.)
- `-rss_limit_mb=2048` — ASan shadow memory plus libFuzzer's accumulating
  coverage counters/corpus push the baseline RSS of the scan-heavy targets past
  512 MB over a run (measured ~410–530 MB) with no per-exec allocation blowup.
  A real unbounded allocation still trips 2048.
- `-max_len=4096` — bounds a single `.env`-sized input.

## What is (and is not) a finding

A **panic / abort / overflow / OOM / hang** is a finding; a graceful `Err`/`None`
return is not. Property assertions per target:

- `parse_pipeline` — never panics through encoding-detect → scan → expand →
  evaluate-gate.
- `ecies_decrypt` — never panics; every decrypt failure maps to exactly one of
  the conditions in `docs/envrypt/crypto-formats.md` §1.4;
  `decrypt(encrypt(pt)) == pt`.
- `upsert_roundtrip` — never panics (primary); `upsert` is deterministic;
  scan-back and scan-back-idempotence are asserted **only on a clean
  `IDENT=value` src**. Over arbitrary or malformed src those two properties do
  not hold (a long tail of scan/placeholder interactions defeats them by
  design); the known cases are pinned as unit tests (e.g.
  `edit::tests::upsert_placeholder_collision_*`).
- `sockeye_decode` — never panics on any bytes fed to `sockeye::decode` (the
  `envrypt-v1` inherited-pipe record parser); every malformed record fails
  closed with a graceful `Err` (bad header / lengths / name / non-hex key /
  short read / trailing byte), and a well-formed record round-trips to its
  64-hex key. This is the production surface behind the sole shipped `unsafe`
  (`from_raw_fd`), which hands the parser an untrusted-parent-controlled
  descriptor.

## Artifact → regression protocol (before any fix merges)

When a run finds a real bug:

1. Reproduce: `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<artifact>`.
2. Minimize: `cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/<artifact>`.
3. **Commit the minimized input as a unit-test regression FIRST** — a small
   `#[test]` in the owning `envrypt` module (crafted to run fast; never commit a
   multi-second artifact). Observe it fail, then fix, then observe it pass. The
   regression test carries a `// FUZZ:` provenance comment naming the target.
4. Only then merge the fix.

## Performance priors (standing)

Measured decisions that stay decided. Anyone proposing one of these brings new
interleaved A/B numbers (12 alternating runs, medians) in the change itself; a
perf claim without a benchmark or disassembly is a guess.

Do NOT, per prior measurement:

1. **Hand-rolled SIMD** for scanning quotes/whitespace/identifiers — lost 1.5–8%
   vs `memchr` in four separate experiments; `.env` tokens are short.
2. **Arena/bump allocation for parse output** — wrong scale (a `.env` yields tens
   of entries; `Vec<Entry>` + `String`/`Cow` is correct here), plus bumpalo's
   never-runs-`Drop` leak class.
3. **String interning / global caches** — pure overhead at this scale, and a
   measured parallel regression elsewhere.
4. **rayon/parallelism on per-value crypto** — ordering is part of the parse
   contract; typical value counts never amortize thread spawn.
5. **Swapping the allocator by default** — the only sanctioned trigger is a
   measured musl regression vs glibc.
6. **Speculative micro-restructuring** (bit-packing, LUT-vs-match rewrites)
   without a disassembly or A/B — LLVM already lowers contiguous `matches!` arms
   to range checks.

Adopted, with the receipts in git history:

- `[profile.release]` = opt-level 3 / **fat** LTO / codegen-units 1 /
  panic=abort / strip=symbols. Fat LTO won its one-time A/B (−8.73% binary size,
  cold-start delta within noise).
- `[profile.bench]` inherits release with `debug = true`, `strip = "none"` for
  symbolized criterion profiles (`crates/envrypt/benches/`).
- **Deferred pending an A/B:** caching the parsed `SecretKey` in ring entries
  for per-value decrypt (`decrypt_bulk_100` is the canary bench).
