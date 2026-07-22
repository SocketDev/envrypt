//! Parser conformance: the tier-1 spec suite run against envrypt's parse pipeline
//! through the runner's library-level [`ParsesTo`] hook. All 88 spec cases must
//! parse to their recorded map, in insertion order. The case-28 encoding pair
//! (`conformance/cases/parser/encoding.json`) runs through the same hook.
//!
//! Multiline and expansion parsing have their own unit tests in
//! `crates/envrypt/src/parse`.

use envrypt_conformance::{
  load_spec_cases, run_spec_suite, spec_cases_path, BaseEnv, Encoding, MapSource, ParsesTo,
  SpecCase,
};
use indexmap::IndexMap;
use std::path::{Path, PathBuf};

/// The standard base env the spec suite parses against.
fn standard_base_env() -> BaseEnv {
  let env = test_support::standard_env();
  let vars = env.vars().to_vec();
  BaseEnv::new(vars).keep_alive(env)
}

/// The runner's `parses_to` hook over envrypt's file-read path: detect the encoding,
/// read the `.env`, then feed `parse_with_ring` an empty ring (the spec corpus is
/// crypto-free) with the case dir as the `$()` child cwd. This mirrors how the envs
/// resolver reads a single `.env` file.
struct CoreParsesTo;

impl ParsesTo for CoreParsesTo {
  fn parses_to(
    &self,
    dir: &Path,
    process_env: &[(String, String)],
  ) -> Result<Vec<(String, String)>, String> {
    let env_path = dir.join(".env");
    let encoding = envrypt::fsio::detect_encoding(&env_path)
      .map_err(|e| format!("detect_encoding({}): {e}", env_path.display()))?;
    let src = envrypt::fsio::read_file_x(&env_path, Some(encoding))
      .map_err(|e| format!("read_file_x({}): {e}", env_path.display()))?;

    let process_env: IndexMap<String, String> = process_env.iter().cloned().collect();
    let mut opts = envrypt::parse::ParseOptions::new(&process_env);
    opts.cwd = Some(dir);
    let out = envrypt::parse::parse_with_ring(&src, &opts);

    if let Some(error) = out.errors.first() {
      return Err(format!("parse error: [{}] {}", error.code, error.message));
    }
    Ok(out.parsed_map().into_iter().collect())
  }
}

/// All 88 tier-1 spec cases parse to their recorded map through the library-level
/// hook (insertion-ordered equality). Case 902 exercises the FF FE BOM path; the 11
/// MACHINE cases exercise the env-precondition merge.
#[test]
fn tier1_spec_cases_pass_against_envrypt() {
  let all = load_spec_cases(&spec_cases_path()).expect("spec.json loads");
  assert_eq!(all.len(), 88);

  // Command-substitution cases assert POSIX-shell output. envrypt runs `$(…)`
  // through the platform shell exactly as Node's `execSync` does — `/bin/sh -c`
  // on POSIX, `cmd.exe /c` on Windows — so on Windows `$(echo "$VAR")` yields
  // the literal (cmd never expands `$VAR`), which matches Node on Windows but
  // not the POSIX golden. Skip them on Windows; POSIX runners cover all 88.
  let skip_cmd_sub = cfg!(windows);
  let cases: Vec<SpecCase> = all
    .into_iter()
    .filter(|c| !(skip_cmd_sub && c.input.contains("$(")))
    .collect();
  if skip_cmd_sub {
    eprintln!(
      "conformance: skipped {} POSIX-shell command-substitution case(s) on Windows (cmd.exe != /bin/sh)",
      88 - cases.len()
    );
  }

  let failures = run_spec_suite(
    &cases,
    &MapSource::ParsesTo(&CoreParsesTo),
    &standard_base_env,
  );
  assert!(
    failures.is_empty(),
    "{}/88 tier-1 spec cases diverged from envrypt's parse pipeline:\n{}",
    failures.len(),
    failures
      .iter()
      .map(|f| format!("--- {}\n{}\n", f.id, f.reason))
      .collect::<String>()
  );
}

fn encoding_cases_path() -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR")).join("../cases/parser/encoding.json")
}

fn load_encoding_cases() -> Vec<SpecCase> {
  let cases = load_spec_cases(&encoding_cases_path()).expect("encoding.json loads");
  assert_eq!(
    cases.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
    ["case28_UTF16LE", "case28_LATIN1"],
    "the case-28 encoding pair"
  );
  cases
}

/// The case-28 inputs materialize the checked-in encoding fixtures byte-for-byte,
/// proving the corpus encodes exactly "write .env.utf16le / .env.latin1 as .env".
#[test]
fn case28_inputs_are_byte_identical_to_the_encoding_fixtures() {
  for (case, fixture) in load_encoding_cases()
    .iter()
    .zip(["root/.env.utf16le", "root/.env.latin1"])
  {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".env");
    envrypt_conformance::write_env_fixture(&path, &case.input, case.encoding).unwrap();
    let materialized = std::fs::read(&path).unwrap();
    let checked_in = std::fs::read(test_support::fixture_path(fixture)).unwrap();
    assert_eq!(
      materialized, checked_in,
      "{}: materialized bytes != {fixture}",
      case.id
    );
  }
  // Sanity: the pair really covers both non-utf8 encodings.
  let encodings: Vec<Encoding> = load_encoding_cases().iter().map(|c| c.encoding).collect();
  assert_eq!(encodings, [Encoding::Utf16Le, Encoding::Latin1]);
}

/// Case 28 through envrypt's parse pipeline.
#[test]
fn case28_encoding_cases_pass_against_envrypt() {
  let cases = load_encoding_cases();
  let failures = run_spec_suite(
    &cases,
    &MapSource::ParsesTo(&CoreParsesTo),
    &standard_base_env,
  );
  assert!(
    failures.is_empty(),
    "case-28 diverged from envrypt's parse pipeline:\n{}",
    failures
      .iter()
      .map(|f| format!("--- {}\n{}\n", f.id, f.reason))
      .collect::<String>()
  );
}
