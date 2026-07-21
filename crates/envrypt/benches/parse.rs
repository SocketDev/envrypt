//! Criterion micro-benches for the parse pipeline (`parse_small`,
//! `parse_spec_corpus`, `parse_expand_heavy`).
//!
//! Correctness of the parse pipeline is pinned by the conformance suites, not
//! here. These benches only measure throughput.
//!
//! Conventions: a fixed corpus (committed under `benches/` or reused from
//! `conformance/`), `black_box` on inputs and outputs, `Throughput::Bytes` for the
//! size-proportional grammar-throughput measurements, and stable benchmark IDs.
//!
//! Benches link default features only.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use envrypt::parse::{parse_with_ring, ParseOptions};
use indexmap::IndexMap;

/// A tiny 2-var `.env` (the `run --quiet -- true` fixture); guards the run-path
/// parse cost.
const PARSE_SMALL_ENV: &str = "HELLO=World\nNODE_ENV=production\n";

/// The 88 tier-1 spec cases, reused verbatim from
/// `conformance/cases/spec/spec.json` so the grammar-wide throughput corpus has a
/// single source of truth. Parsed once at bench setup into the per-case inputs.
const SPEC_JSON: &str = include_str!("../../../conformance/cases/spec/spec.json");

/// 50 vars whose values carry bare `$` noise that forms NEITHER `${...}` nor a
/// `$IDENT` reference (every `$` is followed by a space or a digit) and no `$(`
/// command substitution. This defeats the `memchr(b'$')` short-circuit in
/// `expand()` (the byte IS present) while producing zero replacements — the
/// canary for expand-gate effectiveness (the `expand()` memchr gates).
fn expand_heavy_env() -> String {
  let mut src = String::with_capacity(50 * 40);
  for i in 0..50 {
    // `$ ` (dollar-space) and `$9` (dollar-digit) never match EXPAND_RE
    // `(?<!\\)\$\{([^{}]+)\}|(?<!\\)\$([A-Za-z_][A-Za-z0-9_]*)`; there is no
    // `$(` so the evaluate gate short-circuits too.
    src.push_str(&format!(
      "NOISE_{i:02}=cost $ is $9 and $ {i} bucks off $\n"
    ));
  }
  src
}

/// Parse a single source with an empty process-env and empty ring (the plain
/// unencrypted parse path).
fn parse_plain(src: &str) -> envrypt::parse::ParseOutput {
  let process_env: IndexMap<String, String> = IndexMap::new();
  let opts = ParseOptions::new(&process_env);
  parse_with_ring(src, &opts)
}

/// True when parsing `input` would reach `evaluate()` (parse step 6) with a live
/// command substitution and spawn a real `sh -c` child — i.e. it contains a `$(`
/// that is NOT backslash-escaped. An escaped `\$(` never triggers evaluate, so
/// `117_DONT_CHOKE` (whose sole `$(` is `\$(` inside a single-quoted value) is NOT
/// a spawner and stays in the corpus. A fixed corpus can afford this
/// finer-grained filter (vs a blunt `contains("$(")`) and keep the escaped
/// adversarial case.
fn spawns_subprocess(input: &str) -> bool {
  input
    .match_indices("$(")
    .any(|(idx, _)| idx == 0 || input.as_bytes()[idx - 1] != b'\\')
}

fn spec_inputs() -> Vec<String> {
  let value: serde_json::Value = serde_json::from_str(SPEC_JSON).expect("spec.json is valid JSON");
  value
    .as_array()
    .expect("spec.json is a JSON array of cases")
    .iter()
    .filter_map(|case| case.get("input").and_then(|i| i.as_str()))
    // Drop ONLY the four command-substitution cases (504/505/506/601) whose
    // parse spawns a real `sh -c` child — including them would measure
    // subprocess spawn, not grammar throughput, and a parse micro-bench must
    // never execute its inputs. Everything else stays,
    // including the adversarial `117_DONT_CHOKE` (its `$(` is an escaped `\$(`
    // in a single-quoted value, so it never evaluates) and the 401-408 backtick
    // cases (backticks parse as literal text). Net corpus: 84 of the 88 cases.
    .filter(|input| !spawns_subprocess(input))
    .map(str::to_string)
    .collect()
}

fn bench_parse(c: &mut Criterion) {
  let mut group = c.benchmark_group("parse");

  // parse_small — run-path parse cost.
  group.throughput(Throughput::Bytes(PARSE_SMALL_ENV.len() as u64));
  group.bench_function("parse_small", |b| {
    b.iter(|| black_box(parse_plain(black_box(PARSE_SMALL_ENV))));
  });

  // parse_spec_corpus — grammar-wide throughput over 84 of the 88 spec cases
  // (the 4 command-substitution cases are excluded; see `spec_inputs`).
  let inputs = spec_inputs();
  let total_bytes: usize = inputs.iter().map(String::len).sum();
  group.throughput(Throughput::Bytes(total_bytes as u64));
  group.bench_function("parse_spec_corpus", |b| {
    b.iter(|| {
      for src in &inputs {
        black_box(parse_plain(black_box(src)));
      }
    });
  });

  // parse_expand_heavy — expand-gate effectiveness.
  let heavy = expand_heavy_env();
  group.throughput(Throughput::Bytes(heavy.len() as u64));
  group.bench_function("parse_expand_heavy", |b| {
    b.iter(|| black_box(parse_plain(black_box(&heavy))));
  });

  group.finish();
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
