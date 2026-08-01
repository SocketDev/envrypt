//! Runs one spec case and asserts the parsed map matches, key order included.

use crate::case::SpecCase;
use crate::fixture::write_env_fixture;
use serde_json::Value;
use std::ffi::OsString;
use std::path::Path;

/// A per-case base process environment plus whatever backing state must stay alive
/// until the case finishes (e.g. the fresh `ENVRYPT_CONFIG` tempdir behind
/// `test-support`'s `standard_env()`).
pub struct BaseEnv {
  vars: Vec<(OsString, OsString)>,
  /// Held only so its `Drop` runs after the execution; never read.
  _keepalive: Option<Box<dyn std::any::Any>>,
}

impl BaseEnv {
  /// A base env of plain `(key, value)` pairs with no backing state.
  pub fn new(vars: Vec<(OsString, OsString)>) -> Self {
    Self {
      vars,
      _keepalive: None,
    }
  }

  /// Attach state that must outlive the case execution (e.g. the `TempDir`
  /// behind `ENVRYPT_CONFIG`); it is dropped when the `BaseEnv` is.
  pub fn keep_alive(mut self, state: impl std::any::Any) -> Self {
    self._keepalive = Some(Box::new(state));
    self
  }

  /// The environment pairs.
  pub fn vars(&self) -> &[(OsString, OsString)] {
    &self.vars
  }
}

/// Factory producing a fresh [`BaseEnv`] per case, so every case gets its own
/// `ENVRYPT_CONFIG` tempdir. The in-repo harnesses pass `test_support::standard_env()`
/// through this, which keeps `test-support` a dev-dependency. `Sync` because
/// [`run_spec_suite`] fans cases out across threads.
pub type BaseEnvFn = dyn Fn() -> BaseEnv + Sync;

/// The `parses_to` hook over envrypt's parse pipeline (scan, expand, evaluate, detect
/// encoding). `Sync` because the suite fans cases out across threads, so
/// implementations should be stateless.
pub trait ParsesTo: Sync {
  /// Produce the effective parsed map for the `.env` file inside `dir` (also the cwd
  /// for `$()` command substitution), with `process_env` as the full pre-existing
  /// process environment. Process env wins over file values. Entries come back in
  /// insertion (file) order.
  fn parses_to(
    &self,
    dir: &Path,
    process_env: &[(String, String)],
  ) -> Result<Vec<(String, String)>, String>;
}

/// Where a case's effective parsed map comes from: the [`ParsesTo`] hook. The runner
/// executes everything in-process.
pub enum MapSource<'a> {
  /// Library-level parse via envrypt's parse pipeline.
  ParsesTo(&'a dyn ParsesTo),
}

/// One failed case with a human-readable reason. The suite always runs to completion
/// so a failure report covers every divergent case.
#[derive(Debug)]
pub struct CaseFailure {
  pub id: String,
  pub reason: String,
}

/// Run one spec case: materialize `.env` (honoring the encoding knob) in a fresh temp
/// dir, obtain the parsed map from `source` under a fresh `base_env()` + the case's
/// `env:` preconditions, and assert insertion-ordered equality with `expected`.
pub fn run_spec_case(
  case: &SpecCase,
  source: &MapSource,
  base_env: &BaseEnvFn,
) -> Result<(), String> {
  let dir = tempfile::tempdir().map_err(|e| format!("mkdtemp: {e}"))?;
  write_env_fixture(&dir.path().join(".env"), &case.input, case.encoding)
    .map_err(|e| format!("write .env fixture: {e}"))?;
  // Fresh base env per case: {PATH, ENVRYPT_CONFIG=<fresh mkdtemp>}, supplied by the
  // caller. The value holds its backing state (the config tempdir) alive until the
  // case finishes.
  let base = base_env();

  let actual = match source {
    MapSource::ParsesTo(hook) => {
      let mut process_env: Vec<(String, String)> = base
        .vars()
        .iter()
        .map(|(k, v)| {
          (
            k.to_string_lossy().into_owned(),
            v.to_string_lossy().into_owned(),
          )
        })
        .collect();
      process_env.extend(case.env.iter().cloned());
      hook.parses_to(dir.path(), &process_env)?
    }
  };

  assert_entries(&case.expected, &actual)
}

/// Insertion-ordered parsed-map equality: both key order and values are contract.
fn assert_entries(
  expected: &[(String, String)],
  actual: &[(String, String)],
) -> Result<(), String> {
  if expected == actual {
    return Ok(());
  }
  Err(format!(
    "parsed-map mismatch (insertion order is contract)\n  expected: {}\n  actual:   {}",
    render_entries(expected),
    render_entries(actual),
  ))
}

/// Compact insertion-ordered JSON rendering for failure diffs.
fn render_entries(entries: &[(String, String)]) -> String {
  let mut map = serde_json::Map::with_capacity(entries.len());
  for (k, v) in entries {
    map.insert(k.clone(), Value::String(v.clone()));
  }
  Value::Object(map).to_string()
}

/// Run every case (parallel, one worker per available core), collecting failures
/// sorted by case id. An empty vec means the suite is green. `base_env` is invoked
/// once per case, from worker threads.
pub fn run_spec_suite(
  cases: &[SpecCase],
  source: &MapSource,
  base_env: &BaseEnvFn,
) -> Vec<CaseFailure> {
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::Mutex;

  let next = AtomicUsize::new(0);
  let failures: Mutex<Vec<CaseFailure>> = Mutex::new(Vec::new());
  let workers = std::thread::available_parallelism()
    .map(|n| n.get())
    .unwrap_or(4)
    .min(cases.len().max(1));

  std::thread::scope(|scope| {
    for _ in 0..workers {
      scope.spawn(|| loop {
        let i = next.fetch_add(1, Ordering::Relaxed);
        let Some(case) = cases.get(i) else { break };
        if let Err(reason) = run_spec_case(case, source, base_env) {
          failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(CaseFailure {
              id: case.id.clone(),
              reason,
            });
        }
      });
    }
  });

  let mut failures = failures.into_inner().unwrap_or_else(|e| e.into_inner());
  failures.sort_by(|a, b| a.id.cmp(&b.id));
  failures
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::case::Encoding;

  fn entries(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
      .iter()
      .map(|(k, v)| (k.to_string(), v.to_string()))
      .collect()
  }

  /// The base env, supplied from this dev edge. The `StandardEnv` rides along as
  /// keepalive so its `ENVRYPT_CONFIG` tempdir survives the case.
  fn standard_base_env() -> BaseEnv {
    let env = test_support::standard_env();
    let vars = env.vars().to_vec();
    BaseEnv::new(vars).keep_alive(env)
  }

  #[test]
  fn assert_entries_is_order_sensitive() {
    // serde_json's preserve_order Map compares order-insensitively; the entry
    // vectors must not, because key order is contract.
    let a = entries(&[("A", "1"), ("B", "2")]);
    let b = entries(&[("B", "2"), ("A", "1")]);
    assert!(assert_entries(&a, &a).is_ok());
    let err = assert_entries(&a, &b).unwrap_err();
    assert!(err.contains("insertion order is contract"), "{err}");
  }

  /// The library-level hook contract: it receives the case dir (with `.env`
  /// materialized) and the full process env (standard base env + case
  /// preconditions), and its returned entries are order-asserted.
  struct FakeParse;

  impl ParsesTo for FakeParse {
    fn parses_to(
      &self,
      dir: &Path,
      process_env: &[(String, String)],
    ) -> Result<Vec<(String, String)>, String> {
      assert!(dir.join(".env").is_file(), "fixture must be materialized");
      let get = |k: &str| {
        process_env
          .iter()
          .find(|(key, _)| key == k)
          .map(|(_, v)| v.clone())
      };
      let config = get("ENVRYPT_CONFIG").expect("fresh config dir present");
      assert!(
        Path::new(&config).is_dir(),
        "the BaseEnv keepalive must hold the config tempdir alive during \
                 the execution"
      );
      assert_eq!(
        get("MACHINE").as_deref(),
        Some("machine"),
        "case env merged over base env"
      );
      Ok(vec![("MACHINE".to_string(), "machine".to_string())])
    }
  }

  #[test]
  fn parses_to_hook_gets_dir_and_merged_env_and_is_order_asserted() {
    let case = SpecCase {
      id: "103_MACHINE".to_string(),
      input: "MACHINE=file".to_string(),
      expected: entries(&[("MACHINE", "machine")]),
      env: entries(&[("MACHINE", "machine")]),
      encoding: Encoding::Utf8,
      notes: None,
    };
    run_spec_case(&case, &MapSource::ParsesTo(&FakeParse), &standard_base_env).unwrap();

    let mut wrong = case.clone();
    wrong.expected = entries(&[("MACHINE", "file")]);
    let err =
      run_spec_case(&wrong, &MapSource::ParsesTo(&FakeParse), &standard_base_env).unwrap_err();
    assert!(err.contains("parsed-map mismatch"), "{err}");
  }

  #[test]
  fn base_env_keepalive_drops_with_the_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let env = BaseEnv::new(Vec::new()).keep_alive(dir);
    assert!(path.is_dir(), "keepalive holds the tempdir");
    drop(env);
    assert!(!path.exists(), "dropping the BaseEnv releases the tempdir");
  }
}
