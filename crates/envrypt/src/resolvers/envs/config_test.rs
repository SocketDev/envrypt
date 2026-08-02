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

/// A `.env` line named after the private key is an exfiltration attempt: the
/// process-env precedence rule swaps the planted value for the real key, and the
/// result would otherwise be returned to the caller and injected into `std::env`,
/// where every grandchild inherits it. Whoever writes the `.env` is exactly the
/// adversary the v3 AAD binding defends against, so the key family never leaves
/// the resolver.
#[test]
fn a_planted_private_key_line_cannot_carry_the_real_key_out() {
    let real_key = "1".repeat(64);
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(
        &env_path,
        "ENVRYPT_PRIVATE_KEY=decoy\nENVRYPT_PRIVATE_KEY_STAGING=decoy2\nBASIC=basic\n",
    )
    .unwrap();

    let mut pe = env_map(&[("ENVRYPT_PRIVATE_KEY", &real_key)]);
    let result = run_config_paths(&[&env_path.to_string_lossy()], &mut pe, false);

    assert_eq!(
        result.parsed.get("BASIC").map(String::as_str),
        Some("basic"),
        "an ordinary key still resolves"
    );
    for name in ["ENVRYPT_PRIVATE_KEY", "ENVRYPT_PRIVATE_KEY_STAGING"] {
        assert!(
            !result.parsed.contains_key(name),
            "{name} must not reach the returned map"
        );
    }
    assert!(
        !result.parsed.values().any(|value| value == &real_key),
        "no returned value may carry the private key"
    );
}

/// The same redaction under `overload`, where the planted value — not the real
/// key — is what the file contributes. A private key still never leaves.
#[test]
fn a_planted_private_key_line_is_redacted_under_overload() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "ENVRYPT_PRIVATE_KEY=planted\nBASIC=basic\n").unwrap();

    let mut pe = env_map(&[]);
    let result = run_config_paths(&[&env_path.to_string_lossy()], &mut pe, true);

    assert_eq!(
        result.parsed.get("BASIC").map(String::as_str),
        Some("basic")
    );
    assert!(!result.parsed.contains_key("ENVRYPT_PRIVATE_KEY"));
}

/// The redaction follows the configured naming, not a hard-coded `ENVRYPT_`
/// string — the same [`KeyNaming`] predicate the keyring reads keys with.
#[test]
fn redaction_follows_the_configured_key_naming() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(
        &env_path,
        "APP_PRIVATE_KEY=planted\nENVRYPT_PRIVATE_KEY=not-a-key-under-this-naming\n",
    )
    .unwrap();

    let mut pe = env_map(&[]);
    let (_cap, mut logger) = quiet_logger();
    let options = ConfigOptions {
        path: Some(vec![env_path.to_string_lossy().into_owned()]),
        naming: KeyNaming::from_prefix("APP_"),
        ..Default::default()
    };
    let result = config(&options, &mut pe, &mut logger).unwrap();

    assert!(!result.parsed.contains_key("APP_PRIVATE_KEY"));
    assert_eq!(
        result.parsed.get("ENVRYPT_PRIVATE_KEY").map(String::as_str),
        Some("not-a-key-under-this-naming"),
        "a name outside the configured family is an ordinary variable"
    );
}
