// config() over conformance/fixtures/monorepo. Drives
// `config({process_env, path})` with absolute fixture paths and an injected
// process-env map.
use super::test_helpers::*;
use super::*;

fn run_config(
    paths: &[&str],
    process_env: &mut IndexMap<String, String>,
    overload: bool,
    strict: bool,
    ignore: &[&str],
) -> Result<ConfigResult, RowError> {
    let (_cap, mut logger) = quiet_logger();
    let options = ConfigOptions {
        path: Some(paths.iter().map(|p| p.to_string()).collect()),
        overload,
        strict,
        ignore: ignore.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    config(&options, process_env, &mut logger)
}

#[test]
fn config_backend_env() {
    // config monorepo/apps/backend/.env
    let mut pe = env_map(&[]);
    let result = run_config(
        &[&fixture("monorepo/apps/backend/.env")],
        &mut pe,
        false,
        false,
        &[],
    )
    .unwrap();
    assert_eq!(pe.get("HELLO").map(String::as_str), Some("backend"));
    assert_eq!(
        result.parsed.get("HELLO").map(String::as_str),
        Some("backend")
    );
    assert!(result.error.is_none());
}

#[test]
fn config_backend_env_already_set() {
    // config … already set
    let mut pe = env_map(&[("HELLO", "world")]);
    let result = run_config(
        &[&fixture("monorepo/apps/backend/.env")],
        &mut pe,
        false,
        false,
        &[],
    )
    .unwrap();
    assert_eq!(pe.get("HELLO").map(String::as_str), Some("world"));
    assert_eq!(
        result.parsed.get("HELLO").map(String::as_str),
        Some("world")
    );
    assert!(result.error.is_none());
}

#[test]
fn config_backend_env_already_set_overload() {
    // config … already set --overload
    let mut pe = env_map(&[("HELLO", "world")]);
    let result = run_config(
        &[&fixture("monorepo/apps/backend/.env")],
        &mut pe,
        true,
        false,
        &[],
    )
    .unwrap();
    assert_eq!(pe.get("HELLO").map(String::as_str), Some("backend"));
    assert_eq!(
        result.parsed.get("HELLO").map(String::as_str),
        Some("backend")
    );
    assert!(result.error.is_none());
}

#[test]
fn config_backend_and_frontend_first_wins() {
    // config … backend/.env AND frontend/.env
    let mut pe = env_map(&[]);
    let result = run_config(
        &[
            &fixture("monorepo/apps/backend/.env"),
            &fixture("monorepo/apps/frontend/.env"),
        ],
        &mut pe,
        false,
        false,
        &[],
    )
    .unwrap();
    assert_eq!(pe.get("HELLO").map(String::as_str), Some("backend"));
    assert_eq!(
        result.parsed.get("HELLO").map(String::as_str),
        Some("backend")
    );
    assert!(result.error.is_none());
}

#[test]
fn config_backend_and_frontend_overload_last_wins() {
    // … backend AND frontend --overload
    let mut pe = env_map(&[]);
    let result = run_config(
        &[
            &fixture("monorepo/apps/backend/.env"),
            &fixture("monorepo/apps/frontend/.env"),
        ],
        &mut pe,
        true,
        false,
        &[],
    )
    .unwrap();
    assert_eq!(pe.get("HELLO").map(String::as_str), Some("frontend"));
    assert_eq!(
        result.parsed.get("HELLO").map(String::as_str),
        Some("frontend")
    );
    assert!(result.error.is_none());
}

#[test]
fn config_backend_and_missing_frontend_file() {
    // … AND frontend/missing
    let mut pe = env_map(&[]);
    let result = run_config(
        &[
            &fixture("monorepo/apps/backend/.env"),
            &fixture("monorepo/apps/frontend/missing"),
        ],
        &mut pe,
        false,
        false,
        &[],
    )
    .unwrap();
    assert_eq!(pe.get("HELLO").map(String::as_str), Some("backend"));
    assert_eq!(
        result.parsed.get("HELLO").map(String::as_str),
        Some("backend")
    );
    assert_eq!(result.error.expect("row error").code(), "MISSING_ENV_FILE");
}

#[test]
fn config_backend_and_directory_frontend() {
    // … AND directory frontend
    let mut pe = env_map(&[]);
    let result = run_config(
        &[
            &fixture("monorepo/apps/backend/.env"),
            &fixture("monorepo/apps/frontend"),
        ],
        &mut pe,
        false,
        false,
        &[],
    )
    .unwrap();
    assert_eq!(pe.get("HELLO").map(String::as_str), Some("backend"));
    assert_eq!(
        result.parsed.get("HELLO").map(String::as_str),
        Some("backend")
    );
    assert!(result.error.is_none());
}

#[test]
fn config_backend_and_directory_frontend_strict() {
    // … AND directory frontend --strict
    let mut pe = env_map(&[]);
    let result = run_config(
        &[
            &fixture("monorepo/apps/backend/.env"),
            &fixture("monorepo/apps/frontend"),
        ],
        &mut pe,
        false,
        true,
        &[],
    )
    .unwrap();
    assert_eq!(pe.get("HELLO").map(String::as_str), Some("backend"));
    assert_eq!(
        result.parsed.get("HELLO").map(String::as_str),
        Some("backend")
    );
    assert!(result.error.is_none());
}

#[test]
fn config_strict_with_error_also_ignored_does_not_throw() {
    // … --strict but error ALSO ignored: an ignored MISSING_ENV_FILE must
    // neither throw nor log an error.
    let mut pe = env_map(&[]);
    let (cap, mut logger) = quiet_logger();
    let options = ConfigOptions {
        path: Some(vec![
            fixture("monorepo/apps/backend/.env"),
            fixture("monorepo/apps/frontend/missing"),
        ]),
        strict: true,
        ignore: vec!["MISSING_ENV_FILE".to_string()],
        ..Default::default()
    };
    let result = config(&options, &mut pe, &mut logger).unwrap();
    assert!(result.error.is_none());
    assert!(cap.stderr().is_empty(), "no logger.error output");
}

#[test]
fn config_strict_on_missing_file_throws() {
    // The strict throw contract at the resolver level.
    let mut pe = env_map(&[]);
    let err = run_config(
        &[
            &fixture("monorepo/apps/backend/.env"),
            &fixture("monorepo/apps/frontend/missing"),
        ],
        &mut pe,
        false,
        true,
        &[],
    )
    .unwrap_err();
    assert_eq!(err.code(), "MISSING_ENV_FILE");
}

// --- convention quieting at the config() level ---------------------
//
// A `MISSING_ENV_FILE` error is logged via `logger.error(messageWithHelp)`
// only when no convention is active (convention runs are too noisy); the last
// error is still surfaced in the returned `{ error }`. These tests drive the
// real resolver over an empty temp cwd (every convention file is missing) and
// assert both the empty parse and the silenced stderr.

#[test]
fn config_nextjs_convention_quiets_missing_env_files() {
    // config with a convention: nextjs
    let dir = tempfile::tempdir().unwrap();
    let mut pe = env_map(&[]);
    let (cap, mut logger) = quiet_logger();
    let options = ConfigOptions {
        convention: Some("nextjs".to_string()),
        cwd: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    let result = config(&options, &mut pe, &mut logger).unwrap();
    // nextjs (development) → 4 files, all missing → nothing injected.
    assert!(result.parsed.is_empty());
    // The LAST MISSING_ENV_FILE is still surfaced in the return value...
    assert_eq!(
        result.error.as_ref().map(RowError::code),
        Some("MISSING_ENV_FILE")
    );
    // ...but NONE of the four missing-file errors reaches stderr (quieted).
    assert!(
        cap.stderr().is_empty(),
        "convention quiets MISSING_ENV_FILE; got stderr: {:?}",
        cap.stderr()
    );
}

#[test]
fn config_flow_convention_quiets_missing_env_files() {
    // config with a convention: flow
    let dir = tempfile::tempdir().unwrap();
    let mut pe = env_map(&[]);
    let (cap, mut logger) = quiet_logger();
    let options = ConfigOptions {
        convention: Some("flow".to_string()),
        cwd: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    let result = config(&options, &mut pe, &mut logger).unwrap();
    assert!(result.parsed.is_empty());
    assert_eq!(
        result.error.as_ref().map(RowError::code),
        Some("MISSING_ENV_FILE")
    );
    assert!(cap.stderr().is_empty(), "got stderr: {:?}", cap.stderr());
}

#[test]
fn config_missing_env_file_without_convention_is_logged() {
    // Control (proves the quieting is convention-GATED): no convention → the
    // default `.env` is missing → MISSING_ENV_FILE IS logged to stderr.
    let dir = tempfile::tempdir().unwrap();
    let mut pe = env_map(&[]);
    let (cap, mut logger) = quiet_logger();
    let options = ConfigOptions {
        cwd: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    let result = config(&options, &mut pe, &mut logger).unwrap();
    assert_eq!(
        result.error.as_ref().map(RowError::code),
        Some("MISSING_ENV_FILE")
    );
    assert!(
        cap.stderr()
            .contains("[MISSING_ENV_FILE] missing file (.env)"),
        "missing .env is logged without a convention; got stderr: {:?}",
        cap.stderr()
    );
}

#[test]
fn envs_resolver_decrypts_encrypted_fixture_via_sibling_keys_file() {
    // The encrypted app decrypts through the sibling .env.keys discovery. The
    // checked-in fixture carries `DOTENV_` key names, exercising a
    // consumer-set `DOTENV_` prefix; the default naming is `ENVRYPT_`.
    let mut pe = env_map(&[]);
    let options = EnvsOptions {
        paths: vec![fixture("monorepo/apps/encrypted/.env")],
        naming: KeyNaming::from_prefix("DOTENV_"),
        ..Default::default()
    };
    let out = envs(&options, &mut pe, &mut |_| {});
    let row = &out.processed_envs[0];
    assert!(
        row.errors.is_empty(),
        "no decryption errors: {:?}",
        row.errors
    );
    let hello = pe.get("HELLO").expect("HELLO injected");
    assert!(
        !hello.starts_with("encrypted:"),
        "decrypted via sibling .env.keys, got {hello:?}"
    );
    assert_eq!(out.readable_filepaths.len(), 1);
}

#[test]
fn envs_resolver_reports_decryption_failed_without_keys() {
    // Encrypted .env with no keys: row error
    // `[DECRYPTION_FAILED] could not decrypt HELLO`, and the raw ciphertext is
    // injected into process_env.
    let dir = tempfile::tempdir().unwrap();
    let kp = crate::crypto::keypair();
    let secret = crate::crypto::encrypt(&kp.public_key, "World", true).unwrap();
    std::fs::write(
        dir.path().join(".env"),
        format!(
            "ENVRYPT_PUBLIC_KEY=\"{}\"\nHELLO=\"{}\"\n",
            kp.public_key, secret
        ),
    )
    .unwrap();

    let mut pe = env_map(&[]);
    let options = EnvsOptions {
        paths: vec![".env".to_string()],
        cwd: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    let out = envs(&options, &mut pe, &mut |_| {});
    let row = &out.processed_envs[0];
    assert_eq!(row.errors.len(), 1);
    assert_eq!(row.errors[0].code(), "DECRYPTION_FAILED");
    assert_eq!(
        row.errors[0].message_with_help().unwrap(),
        "[DECRYPTION_FAILED] could not decrypt HELLO. \
           fix: [https://github.com/SocketDev/envrypt/issues/757]"
    );
    assert_eq!(pe.get("HELLO").map(String::as_str), Some(secret.as_str()));
}
