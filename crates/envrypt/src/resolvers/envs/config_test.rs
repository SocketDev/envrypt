// config() over `conformance/fixtures/root/*`. Drives `config()` with absolute
// fixture paths and an injected process-env map. The log-level slice lives in
// output::logger.
use super::test_helpers::*;
use super::*;

fn run_config_paths(
  paths: &[&str],
  process_env: &mut IndexMap<String, String>,
  overload: bool,
) -> ConfigResult {
  let (_cap, mut logger) = quiet_logger();
  let options = ConfigOptions {
    path: Some(paths.iter().map(|p| p.to_string()).collect()),
    overload,
    ..Default::default()
  };
  config(&options, process_env, &mut logger).unwrap()
}

#[test]
fn takes_string_for_path_option() {
  // A string path is the 1-vec case.
  let mut pe = env_map(&[]);
  let result = run_config_paths(&[&fixture("root/.env")], &mut pe, false);
  assert_eq!(
    result.parsed.get("BASIC").map(String::as_str),
    Some("basic")
  );
  assert_eq!(pe.get("BASIC").map(String::as_str), Some("basic"));
}

#[test]
fn takes_array_for_path_option() {
  let mut pe = env_map(&[]);
  let result = run_config_paths(&[&fixture("root/.env")], &mut pe, false);
  assert_eq!(
    result.parsed.get("BASIC").map(String::as_str),
    Some("basic")
  );
  assert_eq!(pe.get("BASIC").map(String::as_str), Some("basic"));
}

#[test]
fn two_files_first_file_wins() {
  let mut pe = env_map(&[]);
  let result = run_config_paths(
    &[&fixture("root/.env.local"), &fixture("root/.env")],
    &mut pe,
    false,
  );
  // in both files — first file wins (.env.local)
  assert_eq!(
    result.parsed.get("BASIC").map(String::as_str),
    Some("local_basic")
  );
  assert_eq!(pe.get("BASIC").map(String::as_str), Some("local_basic"));
  // in .env.local only
  assert_eq!(
    result.parsed.get("LOCAL").map(String::as_str),
    Some("local")
  );
  assert_eq!(pe.get("LOCAL").map(String::as_str), Some("local"));
  // in .env only
  assert_eq!(
    result.parsed.get("SINGLE_QUOTES").map(String::as_str),
    Some("single_quotes")
  );
  assert_eq!(
    pe.get("SINGLE_QUOTES").map(String::as_str),
    Some("single_quotes")
  );
}

#[test]
fn neither_file_used_when_process_env_has_value() {
  let mut pe = env_map(&[("BASIC", "existing")]);
  let result = run_config_paths(
    &[&fixture("root/.env.local"), &fixture("root/.env")],
    &mut pe,
    false,
  );
  assert_eq!(
    result.parsed.get("BASIC").map(String::as_str),
    Some("existing")
  );
  assert_eq!(pe.get("BASIC").map(String::as_str), Some("existing"));
}

#[test]
fn takes_home_directory_tilde_path() {
  // A `~` path expands via the home_dir seam and reads a real file in the
  // fake home.
  let home = tempfile::tempdir().unwrap();
  std::fs::write(home.path().join(".env"), "test=foo").unwrap();
  let mut pe = env_map(&[]);
  let (_cap, mut logger) = quiet_logger();
  let options = ConfigOptions {
    path: Some(vec!["~/.env".to_string()]),
    home_dir: Some(home.path().to_path_buf()),
    ..Default::default()
  };
  let result = config(&options, &mut pe, &mut logger).unwrap();
  assert_eq!(result.parsed.get("test").map(String::as_str), Some("foo"));
  assert!(result.error.is_none());
}

#[test]
fn does_not_write_over_keys_already_in_process_env() {
  let mut pe = env_map(&[("BASIC", "bar")]);
  let result = run_config_paths(&[&fixture("root/.env")], &mut pe, false);
  assert_eq!(result.parsed.get("BASIC").map(String::as_str), Some("bar"));
  assert_eq!(pe.get("BASIC").map(String::as_str), Some("bar"));
}

#[test]
fn writes_over_keys_with_override() {
  // `override: true` collapses to `overload` (overload || override).
  let mut pe = env_map(&[("BASIC", "bar")]);
  let result = run_config_paths(&[&fixture("root/.env")], &mut pe, true);
  assert_eq!(
    result.parsed.get("BASIC").map(String::as_str),
    Some("basic")
  );
  assert_eq!(pe.get("BASIC").map(String::as_str), Some("basic"));
}

#[test]
fn falsy_existing_value_is_not_overwritten() {
  let mut pe = env_map(&[("BASIC", "")]);
  let result = run_config_paths(&[&fixture("root/.env")], &mut pe, false);
  assert_eq!(result.parsed.get("BASIC").map(String::as_str), Some(""));
  assert_eq!(pe.get("BASIC").map(String::as_str), Some(""));
}

#[test]
fn falsy_existing_value_is_overwritten_with_override() {
  let mut pe = env_map(&[("BASIC", "")]);
  let result = run_config_paths(&[&fixture("root/.env")], &mut pe, true);
  assert_eq!(
    result.parsed.get("BASIC").map(String::as_str),
    Some("basic")
  );
  assert_eq!(pe.get("BASIC").map(String::as_str), Some("basic"));
}

#[test]
fn can_write_to_a_different_object_than_process_env() {
  // The `process_env` parameter is the custom target; the real environment
  // is untouched by construction (the resolver never mutates globals).
  let mut my_object = env_map(&[]);
  let result = run_config_paths(&[&fixture("root/.env")], &mut my_object, false);
  assert_eq!(
    result.parsed.get("BASIC").map(String::as_str),
    Some("basic")
  );
  assert_eq!(my_object.get("BASIC").map(String::as_str), Some("basic"));
}

#[test]
fn returns_parsed_object_without_error() {
  let mut pe = env_map(&[]);
  let result = run_config_paths(&[&fixture("root/.env")], &mut pe, false);
  assert!(result.error.is_none());
  assert_eq!(
    result.parsed.get("BASIC").map(String::as_str),
    Some("basic")
  );
}

#[test]
fn returns_errors_thrown_from_reading_file() {
  // The default `.env` is missing in an empty cwd; the error returns in
  // `{ error }` without throwing.
  let dir = tempfile::tempdir().unwrap();
  let mut pe = env_map(&[]);
  let (_cap, mut logger) = quiet_logger();
  let options = ConfigOptions {
    cwd: Some(dir.path().to_path_buf()),
    ..Default::default()
  };
  let result = config(&options, &mut pe, &mut logger).unwrap();
  assert_eq!(result.error.expect("error").code(), "MISSING_ENV_FILE");
  assert!(result.parsed.is_empty());
}
