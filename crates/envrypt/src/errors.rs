//! Error codes, `ISSUE_BY_CODE`, `message_with_help`, and catch-and-log rendering.
//!
//! [`EnvryptError`] is the crate's error value type. It carries a `[CODE] message`
//! string, an optional `fix:` help line, and an optional debug string, and it
//! renders through [`catch_and_log`]. The exact message strings are the contract;
//! callers may match on them, so keep the wording stable.

use std::error::Error;
use std::fmt;

use crate::output::logger::Logger;

/// The `fix:` help target per error code. Most entries are GitHub issue URLs; four
/// are free-text hints (`INVALID_COLOR`, `MISSING_LOG_LEVEL`, `INVALID_PASSPHRASE`,
/// `PRECOMMIT_HOOK_MODIFY_FAILED`). The `help` line is always `fix: [<value>]`
/// regardless of which kind.
pub const ISSUE_BY_CODE: &[(&str, &str)] = &[
    (
        "COMMAND_EXITED_WITH_CODE",
        "https://github.com/SocketDev/envrypt/issues/new",
    ),
    (
        "DECRYPTION_FAILED",
        "https://github.com/SocketDev/envrypt/issues/757",
    ),
    (
        "EXPANSION_TOO_LARGE",
        "drop the self-reference from the value, or raise LoadOptions::max_expand_output_bytes",
    ),
    ("INVALID_COLOR", "must be 256 colors"),
    (
        "INVALID_CONVENTION",
        "https://github.com/SocketDev/envrypt/issues/761",
    ),
    (
        "INVALID_PASSPHRASE",
        "try again with the correct passphrase",
    ),
    (
        "INVALID_PRIVATE_KEY",
        "https://github.com/SocketDev/envrypt/issues/465",
    ),
    (
        "INVALID_PUBLIC_KEY",
        "https://github.com/SocketDev/envrypt/issues/756",
    ),
    (
        "MALFORMED_ENCRYPTED_DATA",
        "https://github.com/SocketDev/envrypt/issues/467",
    ),
    (
        "MISPAIRED_PRIVATE_KEY",
        "https://github.com/SocketDev/envrypt/issues/752",
    ),
    (
        "MISSING_DIRECTORY",
        "https://github.com/SocketDev/envrypt/issues/758",
    ),
    (
        "MISSING_ENV_FILE",
        "https://github.com/SocketDev/envrypt/issues/484",
    ),
    (
        "MISSING_ENV_KEYS_FILE",
        "https://github.com/SocketDev/envrypt/issues/775",
    ),
    (
        "MISSING_ENV_FILES",
        "https://github.com/SocketDev/envrypt/issues/760",
    ),
    (
        "MISSING_KEY",
        "https://github.com/SocketDev/envrypt/issues/759",
    ),
    ("MISSING_LOG_LEVEL", "must be valid log level"),
    (
        "MISSING_PRIVATE_KEY",
        "https://github.com/SocketDev/envrypt/issues/464",
    ),
    (
        "MISSING_PUBLIC_KEY",
        "https://github.com/SocketDev/envrypt/issues/865",
    ),
    (
        "MISSING_VALUE",
        "https://github.com/SocketDev/envrypt/issues/864",
    ),
    ("PRECOMMIT_HOOK_MODIFY_FAILED", "try again or report error"),
    (
        "WRONG_PRIVATE_KEY",
        "https://github.com/SocketDev/envrypt/issues/466",
    ),
];

/// The `ISSUE_BY_CODE` value for `code`, or `None` if the code is unknown.
pub fn issue_by_code(code: &str) -> Option<&'static str> {
    ISSUE_BY_CODE
        .iter()
        .find(|(k, _)| *k == code)
        .map(|(_, v)| *v)
}

/// The `fix: [<value>]` help line for a code. An unknown code yields the literal
/// `fix: [undefined]`, never `None` (Node interpolates `undefined`). That is why
/// [`EnvryptError::custom`] with an unknown code composes
/// `"<message>. fix: [undefined]"`.
fn fix_line(code: &str) -> String {
    format!("fix: [{}]", issue_by_code(code).unwrap_or("undefined"))
}

/// A structured envrypt error: a `[CODE] message` string, an optional `help` line,
/// an optional `code`, a stored `message_with_help` one-liner, and an optional
/// `debug` string. `message_with_help` is stored, not recomputed, because the
/// builders compose it independently of `help`: [`EnvryptError::custom`] composes
/// `"<message>. <help>"` unconditionally, so a help-less custom error's
/// `message_with_help` is the literal `"<message>. undefined"`, which the `help`
/// field alone cannot reproduce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvryptError {
    code: Option<&'static str>,
    message: String,
    help: Option<String>,
    message_with_help: String,
    debug: Option<String>,
}

impl EnvryptError {
    /// The bare `[CODE] message` string (JS `error.message`).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The error code, if any (JS `error.code`).
    pub fn code(&self) -> Option<&'static str> {
        self.code
    }

    /// The help line, if any (JS `error.help`).
    pub fn help(&self) -> Option<&str> {
        self.help.as_deref()
    }

    /// The debug string, if any (JS `error.debug`).
    pub fn debug(&self) -> Option<&str> {
        self.debug.as_deref()
    }

    /// Attach a debug string (chainable), mirroring `options.debug`.
    pub fn with_debug(mut self, debug: impl Into<String>) -> Self {
        self.debug = Some(debug.into());
        self
    }

    /// Override only the `help` field (chainable), leaving `message` and the
    /// already-composed `message_with_help` untouched. This models a post-hoc
    /// `error.help = '...'` mutation: a builder composes `message_with_help` with
    /// the default fix URL, then a caller rewrites `help` with a custom hint, so the
    /// rendered one-liner keeps the default URL while `help` carries the hint.
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Override the stored `message_with_help` one-liner (chainable). Models a caught
    /// error that arrives with a pre-set `message_with_help` distinct from the
    /// composed value, e.g. an "other error" whose `message_with_help = "boom"` sits
    /// alongside a non-`fix:` help.
    pub fn with_message_with_help(mut self, message_with_help: impl Into<String>) -> Self {
        self.message_with_help = message_with_help.into();
        self
    }

    /// The stored one-liner, composed at construction by the builder that produced
    /// it (see [`EnvryptError`]). [`catch_and_log`] renders this.
    pub fn message_with_help(&self) -> String {
        self.message_with_help.clone()
    }

    // -- builders --------------------------------------------------------------

    /// Build a custom error, including the composition rules:
    ///   * a truthy (non-empty) explicit `help` wins;
    ///   * else a `code` yields `fix: [<issue-or-"undefined">]` (unknown code → the
    ///     literal `fix: [undefined]`);
    ///   * else `help` stays absent;
    ///   * `message_with_help` is composed unconditionally as `"<message>. <help>"`,
    ///     so a help-less custom error yields `"<message>. undefined"`.
    pub fn custom(
        message: impl Into<String>,
        code: Option<&'static str>,
        help: Option<String>,
        debug: Option<String>,
    ) -> Self {
        let message = message.into();
        // A truthy explicit help wins; otherwise a non-empty code yields its fix
        // line.
        let help: Option<String> = match help {
            Some(h) if !h.is_empty() => Some(h),
            _ => code.filter(|c| !c.is_empty()).map(fix_line),
        };
        // message_with_help is unconditional; an absent help interpolates the
        // literal "undefined".
        let message_with_help = format!("{}. {}", message, help.as_deref().unwrap_or("undefined"));
        EnvryptError {
            code,
            message,
            help,
            message_with_help,
            debug,
        }
    }

    /// A raw thrown error, as caught by a `try`/`catch` around an fs read or write.
    /// It has no `message_with_help`, so the rendered line is its bare `message`
    /// (e.g. `EACCES: permission denied, open '<path>'`), not the `custom()`
    /// `"<message>. undefined"` composition. [`catch_and_log`] also logs
    /// `ERROR_CODE: <code>` at debug when the error carries a code (Node fs errors
    /// do; pass the libuv errno name). No `help`.
    pub fn raw(message: impl Into<String>, code: Option<&'static str>) -> Self {
        let message = message.into();
        EnvryptError {
            code,
            message: message.clone(),
            help: None,
            message_with_help: message,
            debug: None,
        }
    }

    /// A coded error whose help is the standard `fix: [<issue>]` and whose
    /// `message_with_help` is `"<message>. <help>"`. The per-code builders below all
    /// follow this shape.
    fn coded(code: &'static str, message: String) -> Self {
        let help = fix_line(code);
        let message_with_help = format!("{message}. {help}");
        EnvryptError {
            code: Some(code),
            help: Some(help),
            message,
            message_with_help,
            debug: None,
        }
    }

    /// The `MISSING_ENV_FILE` error; `env_filepath` defaults to `.env`.
    pub fn missing_env_file(env_filepath: Option<&str>) -> Self {
        let path = env_filepath.unwrap_or(".env");
        Self::coded(
            "MISSING_ENV_FILE",
            format!("[MISSING_ENV_FILE] missing file ({path})"),
        )
    }

    /// The `MISSING_ENV_KEYS_FILE` error; defaults to `.env.keys`.
    pub fn missing_env_keys_file(env_keys_filepath: Option<&str>) -> Self {
        let path = env_keys_filepath.unwrap_or(".env.keys");
        Self::coded(
            "MISSING_ENV_KEYS_FILE",
            format!("[MISSING_ENV_KEYS_FILE] missing file ({path})"),
        )
    }

    /// The `MISSING_KEY` error.
    pub fn missing_key(key: &str) -> Self {
        Self::coded("MISSING_KEY", format!("[MISSING_KEY] missing key ({key})"))
    }

    /// The `MISSING_DIRECTORY` error.
    pub fn missing_directory(directory: &str) -> Self {
        Self::coded(
            "MISSING_DIRECTORY",
            format!("[MISSING_DIRECTORY] missing directory ({directory})"),
        )
    }

    /// The `MISSING_ENV_FILES` error.
    pub fn missing_env_files() -> Self {
        Self::coded(
            "MISSING_ENV_FILES",
            "[MISSING_ENV_FILES] no .env* files found".to_string(),
        )
    }

    /// The `MISSING_VALUE` error.
    pub fn missing_value(key: &str) -> Self {
        Self::coded(
            "MISSING_VALUE",
            format!("[MISSING_VALUE] missing value ({key})"),
        )
    }

    /// The `PRECOMMIT_HOOK_MODIFY_FAILED` error; `err_message` is the caught fs
    /// error's message.
    pub fn precommit_hook_modify_failed(err_message: &str) -> Self {
        Self::coded(
            "PRECOMMIT_HOOK_MODIFY_FAILED",
            format!(
                "[PRECOMMIT_HOOK_MODIFY_FAILED] failed to modify pre-commit hook: {err_message}"
            ),
        )
    }

    /// The `MISSING_PUBLIC_KEY` error.
    pub fn missing_public_key() -> Self {
        Self::coded(
            "MISSING_PUBLIC_KEY",
            "[MISSING_PUBLIC_KEY] missing public key".to_string(),
        )
    }

    /// The `INVALID_COLOR` error, raised by [`crate::output::colors::get_color`].
    pub fn invalid_color(color: &str) -> Self {
        Self::coded(
            "INVALID_COLOR",
            format!("[INVALID_COLOR] Invalid color {color}"),
        )
    }

    /// The `MISSING_LOG_LEVEL` error, raised on an unknown log-level name.
    pub fn missing_log_level(level: &str) -> Self {
        Self::coded(
            "MISSING_LOG_LEVEL",
            format!("[MISSING_LOG_LEVEL] missing log level '{level}'. implement in logger"),
        )
    }

    /// The `INVALID_CONVENTION` error, raised for a convention other than `nextjs`
    /// or `flow`.
    pub fn invalid_convention(convention: &str) -> Self {
        Self::coded(
            "INVALID_CONVENTION",
            format!("[INVALID_CONVENTION] invalid convention ({convention})"),
        )
    }

    /// The `DECRYPTION_FAILED` error, used when the envs resolver hits an unresolved
    /// `encrypted:` value or a parse error.
    pub fn decryption_failed(message: &str) -> Self {
        Self::coded(
            "DECRYPTION_FAILED",
            format!("[DECRYPTION_FAILED] {message}"),
        )
    }

    /// The `EXPANSION_TOO_LARGE` error, raised when expanding one `.env` value
    /// would grow past its byte budget. A value that re-inserts itself (say
    /// `SELF="${SELF}$'x"`) doubles on every expansion pass, so the budget is what
    /// stops it; the value is reported, never truncated.
    pub fn expansion_too_large(name: &str, max_output_bytes: usize) -> Self {
        Self::coded(
            "EXPANSION_TOO_LARGE",
            format!(
        "[EXPANSION_TOO_LARGE] expanding '{name}' outgrew its budget: the expansion kept growing \
         past {max_output_bytes} bytes, and a resolved value must fit within that budget"
      ),
        )
    }

    /// The `OP_RESOLUTION_FAILED` error, raised when an opt-in `op://` secret
    /// reference cannot be resolved via the 1Password CLI. Fail-closed: a
    /// requested secret that didn't resolve is an error, never a silent
    /// pass-through. `message` is the already-formatted
    /// [`crate::resolvers::onepassword::OpError`] text.
    pub fn op_resolution_failed(message: &str) -> Self {
        Self::coded(
            "OP_RESOLUTION_FAILED",
            format!("[OP_RESOLUTION_FAILED] {message}"),
        )
    }

    /// The `BW_RESOLUTION_FAILED` error, thrown when a `bw://` (Bitwarden)
    /// reference cannot be resolved via the Bitwarden CLI. Fail-closed: a
    /// requested secret that didn't resolve is an error, never a silent
    /// pass-through. `message` is the already-formatted
    /// [`crate::resolvers::bitwarden::BwError`] text.
    pub fn bw_resolution_failed(message: &str) -> Self {
        Self::coded(
            "BW_RESOLUTION_FAILED",
            format!("[BW_RESOLUTION_FAILED] {message}"),
        )
    }

    /// The `AWS_RESOLUTION_FAILED` error, thrown when an `aws://` (AWS Secrets
    /// Manager) reference cannot be resolved via the AWS CLI. Fail-closed: a
    /// requested secret that didn't resolve is an error, never a silent
    /// pass-through. `message` is the already-formatted
    /// [`crate::resolvers::aws::AwsError`] text.
    pub fn aws_resolution_failed(message: &str) -> Self {
        Self::coded(
            "AWS_RESOLUTION_FAILED",
            format!("[AWS_RESOLUTION_FAILED] {message}"),
        )
    }

    /// The `AZURE_RESOLUTION_FAILED` error, thrown when an `azure://` (Azure Key
    /// Vault) reference cannot be resolved via the Azure CLI. Fail-closed: a
    /// requested secret that didn't resolve is an error, never a silent
    /// pass-through. `message` is the already-formatted
    /// [`crate::resolvers::azure::AzureError`] text.
    pub fn azure_resolution_failed(message: &str) -> Self {
        Self::coded(
            "AZURE_RESOLUTION_FAILED",
            format!("[AZURE_RESOLUTION_FAILED] {message}"),
        )
    }

    /// The `DOPPLER_RESOLUTION_FAILED` error, thrown when a `doppler://` reference
    /// cannot be resolved via the Doppler CLI. Fail-closed: a requested secret that
    /// didn't resolve is an error, never a silent pass-through. `message` is the
    /// already-formatted [`crate::resolvers::doppler::DopplerError`] text.
    pub fn doppler_resolution_failed(message: &str) -> Self {
        Self::coded(
            "DOPPLER_RESOLUTION_FAILED",
            format!("[DOPPLER_RESOLUTION_FAILED] {message}"),
        )
    }

    /// The `GCP_RESOLUTION_FAILED` error, thrown when a `gcp://` (GCP Secret
    /// Manager) reference cannot be resolved via the `gcloud` CLI. Fail-closed: a
    /// requested secret that didn't resolve is an error, never a silent
    /// pass-through. `message` is the already-formatted
    /// [`crate::resolvers::gcp::GcpError`] text.
    pub fn gcp_resolution_failed(message: &str) -> Self {
        Self::coded(
            "GCP_RESOLUTION_FAILED",
            format!("[GCP_RESOLUTION_FAILED] {message}"),
        )
    }

    /// The `INFISICAL_RESOLUTION_FAILED` error, thrown when an `infisical://`
    /// reference cannot be resolved via the Infisical CLI. Fail-closed: a requested
    /// secret that didn't resolve is an error, never a silent pass-through.
    /// `message` is the already-formatted
    /// [`crate::resolvers::infisical::InfisicalError`] text.
    pub fn infisical_resolution_failed(message: &str) -> Self {
        Self::coded(
            "INFISICAL_RESOLUTION_FAILED",
            format!("[INFISICAL_RESOLUTION_FAILED] {message}"),
        )
    }

    /// The `PASS_RESOLUTION_FAILED` error, thrown when a `pass://` (Unix password
    /// store) reference cannot be resolved via the `pass` CLI. Fail-closed: a
    /// requested secret that didn't resolve is an error, never a silent
    /// pass-through. `message` is the already-formatted
    /// [`crate::resolvers::pass::PassError`] text.
    pub fn pass_resolution_failed(message: &str) -> Self {
        Self::coded(
            "PASS_RESOLUTION_FAILED",
            format!("[PASS_RESOLUTION_FAILED] {message}"),
        )
    }

    /// The `VAULT_RESOLUTION_FAILED` error, thrown when a `vault://` (HashiCorp
    /// Vault) reference cannot be resolved via the Vault CLI. Fail-closed: a
    /// requested secret that didn't resolve is an error, never a silent
    /// pass-through. `message` is the already-formatted
    /// [`crate::resolvers::vault::VaultError`] text.
    pub fn vault_resolution_failed(message: &str) -> Self {
        Self::coded(
            "VAULT_RESOLUTION_FAILED",
            format!("[VAULT_RESOLUTION_FAILED] {message}"),
        )
    }
}

impl fmt::Display for EnvryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for EnvryptError {}

/// Render an error to the logger: `logger.error(message_with_help)`, then
/// `logger.debug(debug)` and `logger.debug("ERROR_CODE: <code>")` when present.
/// Never emits a separate `help` line.
pub fn catch_and_log(logger: &mut Logger, error: &EnvryptError) {
    let msg = error.message_with_help();
    if !msg.is_empty() {
        logger.error(&msg);
    }
    if let Some(debug) = error.debug() {
        logger.debug(debug);
    }
    if let Some(code) = error.code() {
        logger.debug(&format!("ERROR_CODE: {code}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::LoggerCapture;

    // ---- Errors builders --------------------------------------------------------

    #[test]
    // tap: tests/lib/helpers/errors.test.js:5-18
    fn errors_custom_with_code_auto_fix_and_debug() {
        let e = EnvryptError::custom(
            "boom",
            Some("MISSING_ENV_FILE"),
            None,
            Some("trace".to_string()),
        );
        assert_eq!(e.code(), Some("MISSING_ENV_FILE"));
        assert_eq!(
            e.help(),
            Some("fix: [https://github.com/SocketDev/envrypt/issues/484]")
        );
        assert_eq!(
            e.message_with_help(),
            "boom. fix: [https://github.com/SocketDev/envrypt/issues/484]"
        );
        assert_eq!(e.debug(), Some("trace"));
    }

    #[test]
    // tap: tests/lib/helpers/errors.test.js:20-31
    fn errors_custom_with_explicit_help_and_no_code() {
        let e = EnvryptError::custom("boom", None, Some("custom help".to_string()), None);
        assert_eq!(e.code(), None);
        assert_eq!(e.help(), Some("custom help"));
        assert_eq!(e.message_with_help(), "boom. custom help");
    }

    #[test]
    // No tap row: this is the `Errors.custom()` composition quirk the tap suite never
    // exercises directly. Expectations probed against src/lib/helpers/errors.js under
    // Node v26.5: `new Errors({message:'boom'}).custom()` composes
    // `` `${message}. ${help}` `` unconditionally, and an absent help interpolates the
    // literal "undefined".
    fn errors_custom_no_code_no_help_yields_undefined_suffix() {
        let e = EnvryptError::custom("boom", None, None, None);
        assert_eq!(e.code(), None);
        assert_eq!(e.help(), None);
        // The JS quirk: `messageWithHelp === 'boom. undefined'`.
        assert_eq!(e.message_with_help(), "boom. undefined");
    }

    #[test]
    // No tap row: `EnvryptError::raw` models a thrown Node error stored in `row.error` /
    // handed to `catchAndLog`. A raw Node error has NO `messageWithHelp`, so the rendered
    // one-liner is its bare `.message` (NOT the `custom()` `. undefined` composition).
    fn errors_raw_has_no_undefined_suffix() {
        let e = EnvryptError::raw(
            "EACCES: permission denied, open '/abs/.env'",
            Some("EACCES"),
        );
        assert_eq!(e.code(), Some("EACCES"));
        assert_eq!(e.help(), None);
        assert_eq!(
            e.message_with_help(),
            "EACCES: permission denied, open '/abs/.env'"
        );
        assert_eq!(e.message(), e.message_with_help());
    }

    #[test]
    // The top-level `catchAndLog` path (env-file / `.env.keys` WRITE throws) renders the
    // bare Node fs message + `ERROR_CODE: <errno>` at debug (live-verified under `--debug`).
    fn catch_and_log_raw_fs_error_bare_message_plus_error_code() {
        let cap = LoggerCapture::new();
        let mut logger = debug_logger(&cap);
        let e = EnvryptError::raw(
            "EACCES: permission denied, open '.env.keys'",
            Some("EACCES"),
        );

        catch_and_log(&mut logger, &e);

        assert_eq!(
            cap.stderr_lines(),
            vec!["☠ EACCES: permission denied, open '.env.keys'"]
        );
        assert_eq!(cap.stdout_lines(), vec!["┆ ERROR_CODE: EACCES"]);
    }

    #[test]
    // A code-less raw error (e.g. a crypto throw) renders just its bare
    // message and emits NO `ERROR_CODE` debug line.
    fn catch_and_log_raw_error_without_code_emits_no_error_code_line() {
        let cap = LoggerCapture::new();
        let mut logger = debug_logger(&cap);
        catch_and_log(&mut logger, &EnvryptError::raw("boom", None));
        assert_eq!(cap.stderr_lines(), vec!["☠ boom"]);
        assert!(cap.stdout_lines().is_empty(), "{:?}", cap.stdout_lines());
    }

    #[test]
    // No tap row: `Errors.custom()` with an unknown code. Probed against errors.js:
    // `e.help = 'fix: [undefined]'` (ISSUE_BY_CODE[code] is undefined) and
    // `messageWithHelp === 'boom. fix: [undefined]'`.
    fn errors_custom_unknown_code_yields_fix_undefined() {
        let e = EnvryptError::custom("boom", Some("OTHER_ERROR"), None, None);
        assert_eq!(e.code(), Some("OTHER_ERROR"));
        assert_eq!(e.help(), Some("fix: [undefined]"));
        assert_eq!(e.message_with_help(), "boom. fix: [undefined]");
    }

    #[test]
    // No tap row: explicit truthy help wins even when a (known) code is present, and an
    // empty-string help is falsy so the code's fix line is used. Probed against errors.js.
    fn errors_custom_help_precedence() {
        let explicit = EnvryptError::custom(
            "boom",
            Some("MISSING_ENV_FILE"),
            Some("custom help".to_string()),
            None,
        );
        assert_eq!(explicit.help(), Some("custom help"));
        assert_eq!(explicit.message_with_help(), "boom. custom help");

        // Empty help is falsy in JS → the code's fix line is composed instead.
        let empty_help =
            EnvryptError::custom("boom", Some("MISSING_ENV_FILE"), Some(String::new()), None);
        assert_eq!(
            empty_help.help(),
            Some("fix: [https://github.com/SocketDev/envrypt/issues/484]")
        );
        assert_eq!(
            empty_help.message_with_help(),
            "boom. fix: [https://github.com/SocketDev/envrypt/issues/484]"
        );
    }

    #[test]
    // tap: tests/lib/helpers/errors.test.js:33-42
    fn errors_missing_env_file_falls_back_to_dot_env() {
        let e = EnvryptError::missing_env_file(None);
        assert_eq!(e.code(), Some("MISSING_ENV_FILE"));
        assert_eq!(e.message(), "[MISSING_ENV_FILE] missing file (.env)");
        assert_eq!(
            e.help(),
            Some("fix: [https://github.com/SocketDev/envrypt/issues/484]")
        );
        assert_eq!(
            e.message_with_help(),
            "[MISSING_ENV_FILE] missing file (.env). fix: [https://github.com/SocketDev/envrypt/issues/484]"
        );
    }

    #[test]
    // tap: tests/lib/helpers/errors.test.js:44-53
    fn errors_missing_env_keys_file_falls_back_to_dot_env_keys() {
        let e = EnvryptError::missing_env_keys_file(None);
        assert_eq!(e.code(), Some("MISSING_ENV_KEYS_FILE"));
        assert_eq!(
            e.message(),
            "[MISSING_ENV_KEYS_FILE] missing file (.env.keys)"
        );
        assert_eq!(
            e.help(),
            Some("fix: [https://github.com/SocketDev/envrypt/issues/775]")
        );
        assert_eq!(
            e.message_with_help(),
            "[MISSING_ENV_KEYS_FILE] missing file (.env.keys). fix: [https://github.com/SocketDev/envrypt/issues/775]"
        );
    }

    #[test]
    // tap: tests/lib/helpers/errors.test.js:55-64
    fn errors_missing_public_key() {
        let e = EnvryptError::missing_public_key();
        assert_eq!(e.code(), Some("MISSING_PUBLIC_KEY"));
        assert_eq!(e.message(), "[MISSING_PUBLIC_KEY] missing public key");
        assert_eq!(
            e.help(),
            Some("fix: [https://github.com/SocketDev/envrypt/issues/865]")
        );
        assert_eq!(
            e.message_with_help(),
            "[MISSING_PUBLIC_KEY] missing public key. fix: [https://github.com/SocketDev/envrypt/issues/865]"
        );
    }

    #[test]
    fn issue_by_code_map_is_verbatim() {
        // The map is part of the contract; spot-check a URL and hints.
        assert_eq!(
            issue_by_code("WRONG_PRIVATE_KEY"),
            Some("https://github.com/SocketDev/envrypt/issues/466")
        );
        assert_eq!(issue_by_code("INVALID_COLOR"), Some("must be 256 colors"));
        assert_eq!(
            issue_by_code("MISSING_LOG_LEVEL"),
            Some("must be valid log level")
        );
        assert_eq!(issue_by_code("NOPE"), None);
        // 21 entries, exactly as errors.js.
        assert_eq!(ISSUE_BY_CODE.len(), 21);
    }

    #[test]
    fn invalid_color_and_missing_log_level_strings() {
        // The colors and logger throw paths.
        assert_eq!(
            EnvryptError::invalid_color("invalid").message(),
            "[INVALID_COLOR] Invalid color invalid"
        );
        assert_eq!(
            EnvryptError::missing_log_level("bogus").message(),
            "[MISSING_LOG_LEVEL] missing log level 'bogus'. implement in logger"
        );
    }

    // ---- catch_and_log rendering via LoggerCapture ------------------------------
    //
    // These assert the exact final rendered strings (the contract). At depth 1 there
    // are no ANSI codes, so the only decorations are the level prefixes (`☠ ` for
    // error, `┆ ` for debug).

    fn debug_logger(cap: &LoggerCapture) -> Logger {
        let mut logger = Logger::new(
            Box::new(cap.stdout_writer()),
            Box::new(cap.stderr_writer()),
            1, // depth 1 => zero ANSI
        );
        logger.set_level("debug"); // so debug() lines actually emit
        logger
    }

    #[test]
    // tap: tests/lib/helpers/catchAndLog.test.js:31-47
    fn catch_and_log_wrong_private_key() {
        let cap = LoggerCapture::new();
        let mut logger = debug_logger(&cap);
        let error = EnvryptError::custom(
            "[WRONG_PRIVATE_KEY] could not decrypt HELLO using private key 'ENVRYPT_PRIVATE_KEY=199bdd6…'",
            Some("WRONG_PRIVATE_KEY"),
            None,
            Some("debug details".to_string()),
        );

        catch_and_log(&mut logger, &error);

        assert_eq!(
            cap.stderr_lines(),
            vec![
                "☠ [WRONG_PRIVATE_KEY] could not decrypt HELLO using private key 'ENVRYPT_PRIVATE_KEY=199bdd6…'. fix: [https://github.com/SocketDev/envrypt/issues/466]"
            ]
        );
        assert_eq!(
            cap.stdout_lines(),
            vec!["┆ debug details", "┆ ERROR_CODE: WRONG_PRIVATE_KEY"]
        );
    }

    #[test]
    // tap: tests/lib/helpers/catchAndLog.test.js:49-61
    fn catch_and_log_missing_private_key() {
        let cap = LoggerCapture::new();
        let mut logger = debug_logger(&cap);
        let error = EnvryptError::custom(
      "[MISSING_PRIVATE_KEY] could not decrypt HELLO using private key 'ENVRYPT_PRIVATE_KEY='",
      Some("MISSING_PRIVATE_KEY"),
      None,
      None,
    );

        catch_and_log(&mut logger, &error);

        assert_eq!(
            cap.stderr_lines(),
            vec![
                "☠ [MISSING_PRIVATE_KEY] could not decrypt HELLO using private key 'ENVRYPT_PRIVATE_KEY='. fix: [https://github.com/SocketDev/envrypt/issues/464]"
            ]
        );
        // no debug string on this error, only the ERROR_CODE debug line
        assert_eq!(
            cap.stdout_lines(),
            vec!["┆ ERROR_CODE: MISSING_PRIVATE_KEY"]
        );
    }

    #[test]
    // tap: tests/lib/helpers/catchAndLog.test.js:63-75
    fn catch_and_log_invalid_public_key() {
        let cap = LoggerCapture::new();
        let mut logger = debug_logger(&cap);
        let error = EnvryptError::custom(
            "[INVALID_PUBLIC_KEY] could not encrypt using public key 'ENVRYPT_PUBLIC_KEY=10248e9…'",
            Some("INVALID_PUBLIC_KEY"),
            None,
            None,
        );

        catch_and_log(&mut logger, &error);

        assert_eq!(
            cap.stderr_lines(),
            vec![
                "☠ [INVALID_PUBLIC_KEY] could not encrypt using public key 'ENVRYPT_PUBLIC_KEY=10248e9…'. fix: [https://github.com/SocketDev/envrypt/issues/756]"
            ]
        );
    }

    #[test]
    // tap: tests/lib/helpers/catchAndLog.test.js:77-94
    fn catch_and_log_other_error_with_help_and_debug() {
        // The tap error is a RAW error (not built via Errors.custom()): it carries an
        // explicit `messageWithHelp = 'boom'` alongside a non-`fix:` help ('help text')
        // and a debug string. catchAndLog uses `messageWithHelp` verbatim and never
        // emits a separate help line. We model it faithfully by overriding the composed
        // one-liner via `with_message_with_help` (custom() alone would compose
        // "boom. help text").
        let cap = LoggerCapture::new();
        let mut logger = debug_logger(&cap);
        let error = EnvryptError::custom(
            "boom",
            Some("OTHER_ERROR"),
            Some("help text".to_string()),
            Some("debug text".to_string()),
        )
        .with_message_with_help("boom");

        catch_and_log(&mut logger, &error);

        assert_eq!(cap.stderr_lines(), vec!["☠ boom"]);
        assert_eq!(
            cap.stdout_lines(),
            vec!["┆ debug text", "┆ ERROR_CODE: OTHER_ERROR"]
        );
    }

    #[test]
    // tap: tests/lib/helpers/catchAndLog.test.js:96-117
    fn catch_and_log_keeps_trailing_periods() {
        let cap = LoggerCapture::new();
        let mut logger = debug_logger(&cap);

        catch_and_log(
            &mut logger,
            &EnvryptError::custom(
                "[WRONG_PRIVATE_KEY] could not decrypt",
                Some("WRONG_PRIVATE_KEY"),
                None,
                None,
            ),
        );
        catch_and_log(
            &mut logger,
            &EnvryptError::custom(
                "[MISSING_PRIVATE_KEY] could not decrypt",
                Some("MISSING_PRIVATE_KEY"),
                None,
                None,
            ),
        );
        catch_and_log(
            &mut logger,
            &EnvryptError::custom(
                "[INVALID_PUBLIC_KEY] could not encrypt",
                Some("INVALID_PUBLIC_KEY"),
                None,
                None,
            ),
        );

        let stderr = cap.stderr_lines();
        assert!(stderr.contains(
            &"☠ [WRONG_PRIVATE_KEY] could not decrypt. fix: [https://github.com/SocketDev/envrypt/issues/466]".to_string()
        ));
        assert!(stderr.contains(
            &"☠ [MISSING_PRIVATE_KEY] could not decrypt. fix: [https://github.com/SocketDev/envrypt/issues/464]".to_string()
        ));
        assert!(stderr.contains(
            &"☠ [INVALID_PUBLIC_KEY] could not encrypt. fix: [https://github.com/SocketDev/envrypt/issues/756]".to_string()
        ));
    }
}
