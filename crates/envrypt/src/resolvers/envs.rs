//! The `.env` resolver plus `config()`-level path construction: loads an
//! ordered file list into a merged, decrypted environment.
//!
//! Each row builds its keyring with [`keyring_local`] (seeded with the row's
//! `publickeys`), then [`fill_ring`] runs the injected [`KeyProvider`]s (callers
//! hand in the armor/keychain providers per their own gating; the resolver runs
//! whatever it is given), then [`parse_with_ring`] consumes it.
//!
//! The ring is rebuilt per row because it depends on per-row inputs: the row's
//! `fk` (the sibling `.env.keys` differs per file), the row's seed public keys,
//! and the live `process_env` (a parsed row can inject `ENVRYPT_PRIVATE_KEY*`
//! values that a later row's ring must observe). A cross-row cache would change
//! behavior; per-process reuse lives at the `Keyring` level for single-parse
//! commands.

use crate::conventions::keynames::{keynames_with, KeyNaming};
use crate::conventions::presets::convention_filepaths;
use crate::errors::EnvryptError;
use crate::keyring::{clear_ring, fill_ring, keyring_local, KeyringLocalOptions, Ring};
use crate::output::logger::Logger;
use crate::parse::{parse_with_ring, public_key_hexes_with, ParseOptions};
use crate::providers::keychain::Exec;
use crate::providers::KeyProvider;
use crate::resolvers::aws::{is_aws_reference, resolve_aws_references};
use crate::resolvers::azure::{is_azure_reference, resolve_azure_references};
use crate::resolvers::bitwarden::{is_bw_reference, resolve_bw_references};
use crate::resolvers::doppler::{is_doppler_reference, resolve_doppler_references};
use crate::resolvers::gcp::{is_gcp_reference, resolve_gcp_references};
use crate::resolvers::infisical::{is_infisical_reference, resolve_infisical_references};
use crate::resolvers::onepassword::{is_op_reference, resolve_op_references};
use crate::resolvers::pass::{is_pass_reference, resolve_pass_references};
use crate::resolvers::vault::{is_vault_reference, resolve_vault_references};
use indexmap::{IndexMap, IndexSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A row-level error. A row carries either a structured error (with
/// `messageWithHelp`) or a raw io/provider error whose `messageWithHelp` is
/// absent. Callers that log `messageWithHelp` unguarded render the raw case as
/// the literal `undefined` (an unreadable `.env` prints `☠ undefined`);
/// [`RowError::catch_message`] falls back to `message`.
#[derive(Clone, Debug)]
pub enum RowError {
  /// A structured [`EnvryptError`] (carries a code and `messageWithHelp`).
  Structured(EnvryptError),
  /// An untyped io/provider error (no `messageWithHelp`).
  Raw { code: String, message: String },
}

impl RowError {
  /// The error code (`""` when absent — never matches an `--ignore` code).
  pub fn code(&self) -> &str {
    match self {
      RowError::Structured(e) => e.code().unwrap_or(""),
      RowError::Raw { code, .. } => code,
    }
  }

  /// The error message.
  pub fn message(&self) -> &str {
    match self {
      RowError::Structured(e) => e.message(),
      RowError::Raw { message, .. } => message,
    }
  }

  /// The message-with-help text; `None` for raw errors (rendered as the literal
  /// string `undefined` by callers).
  pub fn message_with_help(&self) -> Option<String> {
    match self {
      RowError::Structured(e) => Some(e.message_with_help()),
      RowError::Raw { .. } => None,
    }
  }

  /// The message-with-help text, falling back to `message`.
  pub fn catch_message(&self) -> String {
    match self {
      RowError::Structured(e) => e.message_with_help(),
      RowError::Raw { message, .. } => message.clone(),
    }
  }
}

/// One processed `.env` file. `parsed: None` marks an error row: `logger.debug`
/// renders it as the literal `undefined` (`┆ undefined`).
#[derive(Clone, Debug)]
pub struct ProcessedEnv {
  /// Original file path supplied by the caller.
  pub filepath: String,
  pub parsed: Option<IndexMap<String, String>>,
  pub injected: IndexMap<String, String>,
  pub existed: IndexMap<String, String>,
  pub errors: Vec<RowError>,
}

/// Resolver options (`processEnv`/`onStatus` are explicit parameters).
#[derive(Default)]
pub struct EnvsOptions<'a> {
  /// `.env` file paths in load order.
  pub paths: Vec<String>,
  pub overload: bool,
  /// `envKeysFilepath`/`envKeysFile` — already directory-resolved
  /// ([`resolve_env_keys_file`]).
  pub env_keys_file: Option<Vec<String>>,
  /// Providers (keychain per the caller's gating; empty = none).
  pub providers: &'a [Box<dyn KeyProvider>],
  /// Working directory for path resolution and `$()` children. `None` inherits
  /// the process cwd.
  pub cwd: Option<PathBuf>,
  /// The key-identifier naming (default `ENVRYPT_`).
  pub naming: KeyNaming,
}

/// Resolver output: rows plus the original paths of every readable file
/// (insertion-ordered, deduped).
pub struct EnvsOutput {
  pub processed_envs: Vec<ProcessedEnv>,
  pub readable_filepaths: Vec<String>,
}

/// Absolutize and normalize `p` against `cwd`, lexically (no fs access).
pub fn resolve_lexical(cwd: &Path, p: &str) -> PathBuf {
  let raw = if Path::new(p).is_absolute() {
    PathBuf::from(p)
  } else {
    cwd.join(p)
  };
  let mut out = PathBuf::new();
  for component in raw.components() {
    use std::path::Component;
    match component {
      Component::CurDir => {}
      Component::ParentDir => {
        if !out.pop() {
          // above root — Node clamps at root for absolute paths
        }
      }
      other => out.push(other),
    }
  }
  out
}

/// An existing directory is rewritten to `path.join(filepath, filename)`
/// (relative form preserved); anything else (missing paths included) passes
/// through unchanged.
///
/// The join is Node's `path.join` ([`crate::helpers::node_path`]), which
/// normalizes (`path.join('.', '.env')` → `.env`, `'sub/.'` → `sub/.env`). The
/// result is the row's readable filepath, embedded verbatim in the
/// `⟐ injected env (N) from <paths>` banner, so `.`/`./`/`<dir>/.` directory
/// arguments render as plain normalized paths.
pub fn resolve_directory_filepath(filepath: &str, filename: &str, cwd: &Path) -> String {
  let resolved = resolve_lexical(cwd, filepath);
  if resolved.is_dir() {
    // The POSIX join treats `\` as an ordinary character, so a Windows
    // `\`-separated directory must be `/`-normalized first for it to join and
    // read correctly.
    let normalized = crate::helpers::node_path::normalize_path(filepath);
    return crate::helpers::node_path::node_path_join(&[&normalized, filename]);
  }
  filepath.to_string()
}

/// Directory paths become `<dir>/.env.keys`; `None` passes through.
pub fn resolve_env_keys_file(
  env_keys_file: Option<Vec<String>>,
  cwd: &Path,
) -> Option<Vec<String>> {
  env_keys_file.map(|paths| {
    paths
      .iter()
      .map(|p| resolve_directory_filepath(p, ".env.keys", cwd))
      .collect()
  })
}

/// `DOTENV_ENV`, then `NODE_ENV`, else `'development'`.
pub fn conventions_env_name(global_env: &IndexMap<String, String>) -> String {
  global_env
    .get("DOTENV_ENV")
    .filter(|v| !v.is_empty())
    .or_else(|| global_env.get("NODE_ENV").filter(|v| !v.is_empty()))
    .cloned()
    .unwrap_or_else(|| "development".to_string())
}

/// Expands a convention name into an ordered `.env` file-path list.
pub fn conventions(
  convention: &str,
  global_env: &IndexMap<String, String>,
) -> Result<Vec<String>, EnvryptError> {
  let env = conventions_env_name(global_env);
  convention_filepaths(convention, &env)
}

/// Builds the `.env` file list: resolves directory paths and expands
/// conventions.
pub fn build_env_file_paths(
  paths: &[String],
  convention: Option<&str>,
  global_env: &IndexMap<String, String>,
  cwd: &Path,
) -> Result<Vec<String>, EnvryptError> {
  let mut resolved_paths = Vec::new();
  let mut has_directory = false;

  for path in paths {
    let env_filepath = resolve_directory_filepath(path, ".env", cwd);
    if env_filepath == *path {
      resolved_paths.push(path.clone());
      continue;
    }

    has_directory = true;
    if let Some(name) = convention {
      // The directory expands into the convention's file list, each joined
      // into that directory.
      for convention_env in conventions(name, global_env)? {
        resolved_paths.push(resolve_directory_filepath(path, &convention_env, cwd));
      }
    } else {
      resolved_paths.push(env_filepath);
    }
  }

  if let Some(name) = convention {
    if !has_directory {
      // Convention files come first, then explicit entries.
      let mut out = conventions(name, global_env)?;
      out.extend(resolved_paths);
      return Ok(out);
    }
  }

  Ok(resolved_paths)
}

/// Picks env sources. Uses `naming` to detect the private-key names in the process
/// env (default `ENVRYPT_`).
pub fn determine(
  paths: Vec<String>,
  process_env: &IndexMap<String, String>,
  naming: &KeyNaming,
) -> Vec<String> {
  // Keys matching the configured private-key family, in env-object order.
  let private_key_names: Vec<&String> = process_env
    .keys()
    .filter(|k| naming.is_private_key_name(k))
    .collect();

  let defaults = if private_key_names.is_empty() {
    vec![".env".to_string()]
  } else {
    private_key_names
      .iter()
      .map(|name| crate::conventions::guess::guess_private_key_filename_with(name, naming))
      .collect()
  };

  if paths.is_empty() {
    return defaults;
  }
  paths
}

/// Expands a leading `~` in each path to `path.join(homedir, rest)`; no paths
/// means an empty list.
pub fn expand_home_paths(paths: Option<&[String]>, home_dir: Option<&Path>) -> Vec<String> {
  let Some(paths) = paths else {
    return Vec::new();
  };
  paths
    .iter()
    .map(|p| {
      if let Some(rest) = p.strip_prefix('~') {
        let home = home_dir.map(Path::to_path_buf).or_else(dirs_home);
        if let Some(home) = home {
          // `path.join(os.homedir(), filepath.slice(1))` — the rest
          // keeps its leading separator; Path::join with a leading
          // `/` would REPLACE, so trim it first (same result as
          // Node's join, which normalizes the doubled separator).
          // `normalize_path` renders the join `/`-separated so the result
          // matches Node's `path.join` on Windows too (`\` → `/`).
          return crate::helpers::node_path::normalize_path(
            &home.join(rest.trim_start_matches('/')).to_string_lossy(),
          );
        }
      }
      p.clone()
    })
    .collect()
}

/// The home directory: HOME on unix, USERPROFILE on windows (matching Node's
/// `os.homedir()` sources).
fn dirs_home() -> Option<PathBuf> {
  #[cfg(unix)]
  {
    std::env::var_os("HOME").map(PathBuf::from)
  }
  #[cfg(not(unix))]
  {
    std::env::var_os("USERPROFILE").map(PathBuf::from)
  }
}

/// Wraps parse errors via `EnvryptError::custom` (code → `fix:` help); if there
/// are none, emits one aggregated `decryptionFailed` for any still-`encrypted:`
/// parsed values.
fn decrypt_errors(
  parsed: &IndexMap<String, String>,
  parse_errors: &[crate::parse::ParseError],
) -> Vec<RowError> {
  if !parse_errors.is_empty() {
    return parse_errors
      .iter()
      .map(|e| {
        RowError::Structured(EnvryptError::custom(
          e.message.clone(),
          Some(e.code),
          None,
          None,
        ))
      })
      .collect();
  }

  let keys: Vec<&str> = parsed
    .iter()
    .filter(|(_, v)| crate::crypto::is_encrypted(v))
    .map(|(k, _)| k.as_str())
    .collect();
  if keys.is_empty() {
    return Vec::new();
  }
  vec![RowError::Structured(EnvryptError::decryption_failed(
    &format!("could not decrypt {}", keys.join(", ")),
  ))]
}

/// Flatten a non-array parse map (`Vec<String>` singleton values) to strings.
fn flatten(map: &IndexMap<String, Vec<String>>) -> IndexMap<String, String> {
  map
    .iter()
    .map(|(k, v)| (k.clone(), v.last().cloned().unwrap_or_default()))
    .collect()
}

/// Injects parsed values into the process env.
fn inject(process_env: &mut IndexMap<String, String>, parsed: &IndexMap<String, String>) {
  for (key, value) in parsed {
    process_env.insert(key.clone(), value.clone());
  }
}

/// Node-style io error → [`RowError::Raw`] (`{CODE}: {uv message}, open '{path}'`).
/// Surfaces verbatim only via `--strict` or [`RowError::catch_message`]; the
/// non-strict row render prints the literal `undefined` (see [`RowError`]).
fn raw_read_error(err: &std::io::Error, filepath: &Path) -> RowError {
  let code = crate::fsio::errno_name(err);
  RowError::Raw {
    code: code.to_string(),
    message: format!(
      "{code}: {desc}, open '{path}'",
      desc = crate::fsio::uv_description(code),
      path = filepath.display()
    ),
  }
}

/// Shared per-row parse: build the seeded ring (phase 1), run providers
/// (phase 2), parse, record bookkeeping, inject.
#[allow(clippy::too_many_arguments)]
fn parse_row(
  src: &str,
  fk: Vec<PathBuf>,
  options: &EnvsOptions,
  process_env: &mut IndexMap<String, String>,
  row: &mut ProcessedEnv,
  on_status: &mut dyn FnMut(&str),
  cwd: &Path,
) {
  // Seed the ring with the source's public keys.
  let mut seed_ring = Ring::new();
  for public_key in public_key_hexes_with(src, &options.naming) {
    seed_ring.entry(public_key).or_default();
  }

  let mut ring = keyring_local(&KeyringLocalOptions {
    process_env,
    fk,
    seed_ring,
    naming: &options.naming,
  });

  if let Err(e) = fill_ring(&mut ring, options.providers, on_status) {
    clear_ring(&mut ring);
    // A provider failure aborts the row's parse and becomes a raw error (no
    // messageWithHelp).
    row.errors = vec![RowError::Raw {
      code: String::new(),
      message: e.0,
    }];
    return;
  }

  let mut parse_options = ParseOptions::new(process_env);
  parse_options.overload = options.overload;
  parse_options.ring = &ring;
  parse_options.cwd = Some(cwd);
  parse_options.naming = &options.naming;
  let output = parse_with_ring(src, &parse_options);
  clear_ring(&mut ring);

  let parsed = flatten(&output.parsed);
  row.injected = flatten(&output.injected);
  row.existed = flatten(&output.existed);
  row.errors = decrypt_errors(&parsed, &output.errors);
  inject(process_env, &parsed);
  row.parsed = Some(parsed);
}

/// Reads and parses one env file into a row.
fn inject_env_file(
  path: &str,
  options: &EnvsOptions,
  process_env: &mut IndexMap<String, String>,
  readable_filepaths: &mut Vec<String>,
  on_status: &mut dyn FnMut(&str),
  cwd: &Path,
) -> ProcessedEnv {
  let mut row = ProcessedEnv {
    filepath: path.to_string(),
    parsed: None,
    injected: IndexMap::new(),
    existed: IndexMap::new(),
    errors: Vec::new(),
  };

  let filepath = resolve_lexical(cwd, path);
  let src = crate::fsio::detect_encoding(&filepath)
    .and_then(|encoding| crate::fsio::read_file_x(&filepath, Some(encoding)));
  let src = match src {
    Ok(src) => src,
    Err(e) => {
      // ENOENT/EISDIR → MISSING_ENV_FILE with the original value; any other
      // io error stays raw.
      let code = crate::fsio::errno_name(&e);
      if code == "ENOENT" || code == "EISDIR" {
        row.errors = vec![RowError::Structured(EnvryptError::missing_env_file(Some(
          path,
        )))];
      } else {
        row.errors = vec![raw_read_error(&e, &filepath)];
      }
      return row;
    }
  };

  if !readable_filepaths.iter().any(|readable| readable == path) {
    readable_filepaths.push(path.to_string());
  }

  // With no explicit `-fk`: if the process env already carries the private key,
  // default to the CWD-relative `.env.keys`; otherwise discover the file's
  // sibling `.env.keys`.
  let names = keynames_with(&filepath.to_string_lossy(), "", &options.naming);
  let fk: Vec<PathBuf> = match &options.env_keys_file {
    Some(paths) => paths.iter().map(|p| resolve_lexical(cwd, p)).collect(),
    None => {
      let has_private_key = process_env
        .get(&names.private_key_name)
        .is_some_and(|v| !v.is_empty());
      if has_private_key {
        vec![cwd.join(".env.keys")]
      } else {
        vec![filepath
          .parent()
          .unwrap_or_else(|| Path::new(""))
          .join(".env.keys")]
      }
    }
  };

  parse_row(&src, fk, options, process_env, &mut row, on_status, cwd);
  row
}

/// Processes every file, mutating `process_env` in place (decrypt-then-inject;
/// the file on disk is never modified).
pub fn envs(
  options: &EnvsOptions,
  process_env: &mut IndexMap<String, String>,
  on_status: &mut dyn FnMut(&str),
) -> EnvsOutput {
  #[expect(
    clippy::disallowed_methods,
    reason = "public API boundary: `options.cwd = None` documents falling back to the process cwd (dotenvx parity)"
  )]
  let cwd = options
    .cwd
    .clone()
    .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

  let mut processed_envs = Vec::new();
  let mut readable_filepaths = Vec::new();

  for path in &options.paths {
    processed_envs.push(inject_env_file(
      path,
      options,
      process_env,
      &mut readable_filepaths,
      on_status,
      &cwd,
    ));
  }

  EnvsOutput {
    processed_envs,
    readable_filepaths,
  }
}

/// `config()` result: the merged parsed map plus the last row error.
#[derive(Debug)]
pub struct ConfigResult {
  pub parsed: IndexMap<String, String>,
  pub error: Option<RowError>,
}

/// `config()` options.
pub struct ConfigOptions<'a> {
  /// `options.path` — string collapsed to a 1-vec by the caller; `None` = unset.
  pub path: Option<Vec<String>>,
  /// `options.overload || options.override`.
  pub overload: bool,
  pub strict: bool,
  pub ignore: Vec<String>,
  pub env_keys_file: Option<Vec<String>>,
  pub convention: Option<String>,
  pub providers: &'a [Box<dyn KeyProvider>],
  /// The real process env (source of conventions' `DOTENV_ENV`/`NODE_ENV`),
  /// distinct from the `process_env` target. The convention comes only from
  /// `ConfigOptions.convention`.
  pub global_env: IndexMap<String, String>,
  /// `os.homedir()` seam for `~` expansion.
  pub home_dir: Option<PathBuf>,
  pub cwd: Option<PathBuf>,
  /// The key-identifier naming (default `ENVRYPT_`).
  pub naming: KeyNaming,
  /// Opt-in 1Password `op://` resolution. `Some(exec)` resolves every `op://`
  /// value through `op read` via this bounded-timeout [`Exec`] seam
  /// (fail-closed); `None` (the default) leaves `op://` strings verbatim, so
  /// nothing shells out unless the caller asked for it.
  pub op_exec: Option<&'a dyn Exec>,
  /// Per-`op read` deadline when `op_exec` is set (default
  /// [`crate::resolvers::onepassword::DEFAULT_OP_TIMEOUT`]).
  pub op_timeout: Duration,
  /// Opt-in Bitwarden `bw://` resolution. `Some(exec)` resolves every `bw://`
  /// value through `bw get` via this bounded-timeout [`Exec`] seam (fail-closed);
  /// `None` (the default) leaves `bw://` strings verbatim, so nothing shells out
  /// unless the caller asked for it.
  pub bw_exec: Option<&'a dyn Exec>,
  /// Per-`bw get` deadline when `bw_exec` is set (default
  /// [`crate::resolvers::bitwarden::DEFAULT_BW_TIMEOUT`]).
  pub bw_timeout: Duration,
  /// Opt-in AWS Secrets Manager `aws://` resolution. `Some(exec)` resolves every
  /// `aws://` value through `aws secretsmanager get-secret-value` via this
  /// bounded-timeout [`Exec`] seam (fail-closed); `None` (the default) leaves
  /// `aws://` strings verbatim, so nothing shells out unless the caller asked for
  /// it.
  pub aws_exec: Option<&'a dyn Exec>,
  /// Per-`aws secretsmanager get-secret-value` deadline when `aws_exec` is set
  /// (default [`crate::resolvers::aws::DEFAULT_AWS_TIMEOUT`]).
  pub aws_timeout: Duration,
  /// Opt-in Azure Key Vault `azure://` resolution. `Some(exec)` resolves every
  /// `azure://` value through `az keyvault secret show` via this bounded-timeout
  /// [`Exec`] seam (fail-closed); `None` (the default) leaves `azure://` strings
  /// verbatim, so nothing shells out unless the caller asked for it.
  pub azure_exec: Option<&'a dyn Exec>,
  /// Per-`az keyvault secret show` deadline when `azure_exec` is set (default
  /// [`crate::resolvers::azure::DEFAULT_AZURE_TIMEOUT`]).
  pub azure_timeout: Duration,
  /// Opt-in Doppler `doppler://` resolution. `Some(exec)` resolves every
  /// `doppler://` value through `doppler secrets get` via this bounded-timeout
  /// [`Exec`] seam (fail-closed); `None` (the default) leaves `doppler://` strings
  /// verbatim, so nothing shells out unless the caller asked for it.
  pub doppler_exec: Option<&'a dyn Exec>,
  /// Per-`doppler secrets get` deadline when `doppler_exec` is set (default
  /// [`crate::resolvers::doppler::DEFAULT_DOPPLER_TIMEOUT`]).
  pub doppler_timeout: Duration,
  /// Opt-in GCP Secret Manager `gcp://` resolution. `Some(exec)` resolves every
  /// `gcp://` value through `gcloud secrets versions access` via this
  /// bounded-timeout [`Exec`] seam (fail-closed); `None` (the default) leaves
  /// `gcp://` strings verbatim, so nothing shells out unless the caller asked for
  /// it.
  pub gcp_exec: Option<&'a dyn Exec>,
  /// Per-`gcloud secrets versions access` deadline when `gcp_exec` is set (default
  /// [`crate::resolvers::gcp::DEFAULT_GCP_TIMEOUT`]).
  pub gcp_timeout: Duration,
  /// Opt-in Infisical `infisical://` resolution. `Some(exec)` resolves every
  /// `infisical://` value through `infisical secrets get` via this bounded-timeout
  /// [`Exec`] seam (fail-closed); `None` (the default) leaves `infisical://`
  /// strings verbatim, so nothing shells out unless the caller asked for it.
  pub infisical_exec: Option<&'a dyn Exec>,
  /// Per-`infisical secrets get` deadline when `infisical_exec` is set (default
  /// [`crate::resolvers::infisical::DEFAULT_INFISICAL_TIMEOUT`]).
  pub infisical_timeout: Duration,
  /// Opt-in `pass` (Unix password store) `pass://` resolution. `Some(exec)`
  /// resolves every `pass://` value through `pass show` via this bounded-timeout
  /// [`Exec`] seam (fail-closed); `None` (the default) leaves `pass://` strings
  /// verbatim, so nothing shells out unless the caller asked for it.
  pub pass_exec: Option<&'a dyn Exec>,
  /// Per-`pass show` deadline when `pass_exec` is set (default
  /// [`crate::resolvers::pass::DEFAULT_PASS_TIMEOUT`]).
  pub pass_timeout: Duration,
  /// Opt-in HashiCorp Vault `vault://` resolution. `Some(exec)` resolves every
  /// `vault://` value through `vault kv get` via this bounded-timeout [`Exec`]
  /// seam (fail-closed); `None` (the default) leaves `vault://` strings verbatim,
  /// so nothing shells out unless the caller asked for it.
  pub vault_exec: Option<&'a dyn Exec>,
  /// Per-`vault kv get` deadline when `vault_exec` is set (default
  /// [`crate::resolvers::vault::DEFAULT_VAULT_TIMEOUT`]).
  pub vault_timeout: Duration,
}

impl Default for ConfigOptions<'_> {
  fn default() -> Self {
    ConfigOptions {
      path: None,
      overload: false,
      strict: false,
      ignore: Vec::new(),
      env_keys_file: None,
      convention: None,
      providers: &[],
      global_env: IndexMap::new(),
      home_dir: None,
      cwd: None,
      naming: KeyNaming::default(),
      op_exec: None,
      op_timeout: crate::resolvers::onepassword::DEFAULT_OP_TIMEOUT,
      bw_exec: None,
      bw_timeout: crate::resolvers::bitwarden::DEFAULT_BW_TIMEOUT,
      aws_exec: None,
      aws_timeout: crate::resolvers::aws::DEFAULT_AWS_TIMEOUT,
      azure_exec: None,
      azure_timeout: crate::resolvers::azure::DEFAULT_AZURE_TIMEOUT,
      doppler_exec: None,
      doppler_timeout: crate::resolvers::doppler::DEFAULT_DOPPLER_TIMEOUT,
      gcp_exec: None,
      gcp_timeout: crate::resolvers::gcp::DEFAULT_GCP_TIMEOUT,
      infisical_exec: None,
      infisical_timeout: crate::resolvers::infisical::DEFAULT_INFISICAL_TIMEOUT,
      pass_exec: None,
      pass_timeout: crate::resolvers::pass::DEFAULT_PASS_TIMEOUT,
      vault_exec: None,
      vault_timeout: crate::resolvers::vault::DEFAULT_VAULT_TIMEOUT,
    }
  }
}

/// Builds the env list, resolves it, logs, and merges `{parsed, error}`. Under
/// `strict`, a row error returns `Err`.
pub fn config(
  options: &ConfigOptions,
  process_env: &mut IndexMap<String, String>,
  logger: &mut Logger,
) -> Result<ConfigResult, RowError> {
  #[expect(
    clippy::disallowed_methods,
    reason = "public API boundary: `options.cwd = None` documents falling back to the process cwd (dotenvx parity)"
  )]
  let cwd = options
    .cwd
    .clone()
    .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

  // The convention comes only from the explicit `convention` option.
  let convention: Option<String> = options.convention.clone();

  // Path entries get directory resolution and convention prefixing. A build
  // failure (INVALID_CONVENTION) surfaces below.
  let option_paths = expand_home_paths(options.path.as_deref(), options.home_dir.as_deref());
  let mut paths = match build_env_file_paths(
    &option_paths,
    convention.as_deref(),
    &options.global_env,
    &cwd,
  ) {
    Ok(list) => list,
    Err(error) => {
      let error = RowError::Structured(error);
      if options.strict {
        return Err(error);
      }
      logger.error(&error.message_with_help().unwrap_or_default());
      return Ok(ConfigResult {
        parsed: IndexMap::new(),
        error: Some(error),
      });
    }
  };

  paths = determine(paths, process_env, &options.naming);

  let resolver_options = EnvsOptions {
    paths,
    overload: options.overload,
    env_keys_file: resolve_env_keys_file(options.env_keys_file.clone(), &cwd),
    providers: options.providers,
    cwd: Some(cwd),
    naming: options.naming.clone(),
  };
  let output = envs(&resolver_options, process_env, &mut |_| {});

  let mut last_error: Option<RowError> = None;
  let mut parsed_all: IndexMap<String, String> = IndexMap::new();

  for processed_env in &output.processed_envs {
    logger.verbose(&format!(
      "loading env from {} ({})",
      processed_env.filepath,
      resolve_lexical(
        resolver_options.cwd.as_deref().unwrap_or(Path::new("")),
        &processed_env.filepath
      )
      .display()
    ));

    for error in &processed_env.errors {
      if options.ignore.iter().any(|code| code == error.code()) {
        logger.verbose(&format!("ignored: {}", error.message()));
        continue;
      }

      if options.strict {
        return Err(error.clone()); // strict and not ignored: propagate
      }

      last_error = Some(error.clone());

      // MISSING_ENV_FILE stays quiet under a convention.
      if error.code() == "MISSING_ENV_FILE" && convention.is_some() {
        // intentionally quiet
      } else {
        // Logs `messageWithHelp`; raw errors render as the literal
        // `undefined` (see RowError).
        logger.error(
          &error
            .message_with_help()
            .unwrap_or_else(|| "undefined".into()),
        );
      }
    }

    // Merge injected then existed into parsed_all; existed wins.
    for (k, v) in &processed_env.injected {
      parsed_all.insert(k.clone(), v.clone());
    }
    for (k, v) in &processed_env.existed {
      parsed_all.insert(k.clone(), v.clone());
    }

    // Debug the parsed map (`undefined` on error rows).
    logger.debug(&debug_parsed_line(processed_env.parsed.as_ref()));

    for (key, value) in &processed_env.injected {
      logger.verbose(&format!("{key} set"));
      logger.debug(&format!("{key} set to {value}"));
    }
    for (key, value) in &processed_env.existed {
      logger.verbose(&format!(
        "{key} pre-exists (protip: use --overload to override)"
      ));
      logger.debug(&format!(
        "{key} pre-exists as {value} (protip: use --overload to override)"
      ));
    }
  }

  let mut msg = format!(
    "injected env ({})",
    unique_injected_count(&output.processed_envs)
  );
  if !output.readable_filepaths.is_empty() {
    msg.push_str(&format!(" from {}", output.readable_filepaths.join(", ")));
  }
  logger.success(&format!("⟐ {msg}"));

  // Opt-in 1Password `op://` resolution over the merged map. Runs only when the
  // caller threaded an `Exec` (else `op://` strings stay verbatim). Fail-closed:
  // under strict a resolution failure returns `Err`; otherwise it is logged and
  // recorded, and the failing value keeps its literal `op://` form — never a
  // silently-wrong secret. Resolve once here, then mirror each resolved secret
  // into the injected `process_env` so a spawned child reads the real value, not
  // the reference (only overwriting keys still holding the original `op://`).
  if let Some(op_exec) = options.op_exec {
    let op_keys: Vec<String> = parsed_all
      .iter()
      .filter(|(_, value)| is_op_reference(value))
      .map(|(key, _)| key.clone())
      .collect();
    match resolve_op_references(&mut parsed_all, op_exec, options.op_timeout) {
      Ok(()) => {
        for key in op_keys {
          if let Some(secret) = parsed_all.get(&key) {
            let injected_is_reference = process_env
              .get(&key)
              .is_some_and(|value| is_op_reference(value));
            if injected_is_reference {
              process_env.insert(key, secret.clone());
            }
          }
        }
      }
      Err(op_err) => {
        let error = RowError::Structured(EnvryptError::op_resolution_failed(&op_err.message()));
        if options.strict {
          return Err(error);
        }
        logger.error(
          &error
            .message_with_help()
            .unwrap_or_else(|| error.catch_message()),
        );
        last_error = Some(error);
      }
    }
  }

  // Opt-in Bitwarden `bw://` resolution — the companion to the `op://` pass
  // above, over the same merged map. Runs only when `bw_exec` is threaded.
  // Fail-closed identically: strict → `Err`; else log + record, and the failing
  // value keeps its literal `bw://` form. Resolved secrets mirror into
  // `process_env` (only overwriting keys still holding the original `bw://`).
  if let Some(bw_exec) = options.bw_exec {
    let bw_keys: Vec<String> = parsed_all
      .iter()
      .filter(|(_, value)| is_bw_reference(value))
      .map(|(key, _)| key.clone())
      .collect();
    match resolve_bw_references(&mut parsed_all, bw_exec, options.bw_timeout) {
      Ok(()) => {
        for key in bw_keys {
          if let Some(secret) = parsed_all.get(&key) {
            let injected_is_reference = process_env
              .get(&key)
              .is_some_and(|value| is_bw_reference(value));
            if injected_is_reference {
              process_env.insert(key, secret.clone());
            }
          }
        }
      }
      Err(bw_err) => {
        let error = RowError::Structured(EnvryptError::bw_resolution_failed(&bw_err.message()));
        if options.strict {
          return Err(error);
        }
        logger.error(
          &error
            .message_with_help()
            .unwrap_or_else(|| error.catch_message()),
        );
        last_error = Some(error);
      }
    }
  }

  // Opt-in AWS Secrets Manager `aws://` resolution — the companion to the passes
  // above, over the same merged map. Runs only when `aws_exec` is threaded.
  // Fail-closed identically: strict → `Err`; else log + record, and the failing
  // value keeps its literal `aws://` form. Resolved secrets mirror into
  // `process_env` (only overwriting keys still holding the original `aws://`).
  if let Some(aws_exec) = options.aws_exec {
    let aws_keys: Vec<String> = parsed_all
      .iter()
      .filter(|(_, value)| is_aws_reference(value))
      .map(|(key, _)| key.clone())
      .collect();
    match resolve_aws_references(&mut parsed_all, aws_exec, options.aws_timeout) {
      Ok(()) => {
        for key in aws_keys {
          if let Some(secret) = parsed_all.get(&key) {
            let injected_is_reference = process_env
              .get(&key)
              .is_some_and(|value| is_aws_reference(value));
            if injected_is_reference {
              process_env.insert(key, secret.clone());
            }
          }
        }
      }
      Err(aws_err) => {
        let error = RowError::Structured(EnvryptError::aws_resolution_failed(&aws_err.message()));
        if options.strict {
          return Err(error);
        }
        logger.error(
          &error
            .message_with_help()
            .unwrap_or_else(|| error.catch_message()),
        );
        last_error = Some(error);
      }
    }
  }

  // Opt-in Azure Key Vault `azure://` resolution — same fail-closed shape over the
  // merged map, running only when `azure_exec` is threaded. Resolved secrets
  // mirror into `process_env` (only overwriting keys still holding `azure://`).
  if let Some(azure_exec) = options.azure_exec {
    let azure_keys: Vec<String> = parsed_all
      .iter()
      .filter(|(_, value)| is_azure_reference(value))
      .map(|(key, _)| key.clone())
      .collect();
    match resolve_azure_references(&mut parsed_all, azure_exec, options.azure_timeout) {
      Ok(()) => {
        for key in azure_keys {
          if let Some(secret) = parsed_all.get(&key) {
            let injected_is_reference = process_env
              .get(&key)
              .is_some_and(|value| is_azure_reference(value));
            if injected_is_reference {
              process_env.insert(key, secret.clone());
            }
          }
        }
      }
      Err(azure_err) => {
        let error =
          RowError::Structured(EnvryptError::azure_resolution_failed(&azure_err.message()));
        if options.strict {
          return Err(error);
        }
        logger.error(
          &error
            .message_with_help()
            .unwrap_or_else(|| error.catch_message()),
        );
        last_error = Some(error);
      }
    }
  }

  // Opt-in Doppler `doppler://` resolution — same fail-closed shape over the
  // merged map, running only when `doppler_exec` is threaded. Resolved secrets
  // mirror into `process_env` (only overwriting keys still holding `doppler://`).
  if let Some(doppler_exec) = options.doppler_exec {
    let doppler_keys: Vec<String> = parsed_all
      .iter()
      .filter(|(_, value)| is_doppler_reference(value))
      .map(|(key, _)| key.clone())
      .collect();
    match resolve_doppler_references(&mut parsed_all, doppler_exec, options.doppler_timeout) {
      Ok(()) => {
        for key in doppler_keys {
          if let Some(secret) = parsed_all.get(&key) {
            let injected_is_reference = process_env
              .get(&key)
              .is_some_and(|value| is_doppler_reference(value));
            if injected_is_reference {
              process_env.insert(key, secret.clone());
            }
          }
        }
      }
      Err(doppler_err) => {
        let error = RowError::Structured(EnvryptError::doppler_resolution_failed(
          &doppler_err.message(),
        ));
        if options.strict {
          return Err(error);
        }
        logger.error(
          &error
            .message_with_help()
            .unwrap_or_else(|| error.catch_message()),
        );
        last_error = Some(error);
      }
    }
  }

  // Opt-in GCP Secret Manager `gcp://` resolution — same fail-closed shape over
  // the merged map, running only when `gcp_exec` is threaded. Resolved secrets
  // mirror into `process_env` (only overwriting keys still holding `gcp://`).
  if let Some(gcp_exec) = options.gcp_exec {
    let gcp_keys: Vec<String> = parsed_all
      .iter()
      .filter(|(_, value)| is_gcp_reference(value))
      .map(|(key, _)| key.clone())
      .collect();
    match resolve_gcp_references(&mut parsed_all, gcp_exec, options.gcp_timeout) {
      Ok(()) => {
        for key in gcp_keys {
          if let Some(secret) = parsed_all.get(&key) {
            let injected_is_reference = process_env
              .get(&key)
              .is_some_and(|value| is_gcp_reference(value));
            if injected_is_reference {
              process_env.insert(key, secret.clone());
            }
          }
        }
      }
      Err(gcp_err) => {
        let error = RowError::Structured(EnvryptError::gcp_resolution_failed(&gcp_err.message()));
        if options.strict {
          return Err(error);
        }
        logger.error(
          &error
            .message_with_help()
            .unwrap_or_else(|| error.catch_message()),
        );
        last_error = Some(error);
      }
    }
  }

  // Opt-in Infisical `infisical://` resolution — same fail-closed shape over the
  // merged map, running only when `infisical_exec` is threaded. Resolved secrets
  // mirror into `process_env` (only overwriting keys still holding `infisical://`).
  if let Some(infisical_exec) = options.infisical_exec {
    let infisical_keys: Vec<String> = parsed_all
      .iter()
      .filter(|(_, value)| is_infisical_reference(value))
      .map(|(key, _)| key.clone())
      .collect();
    match resolve_infisical_references(&mut parsed_all, infisical_exec, options.infisical_timeout) {
      Ok(()) => {
        for key in infisical_keys {
          if let Some(secret) = parsed_all.get(&key) {
            let injected_is_reference = process_env
              .get(&key)
              .is_some_and(|value| is_infisical_reference(value));
            if injected_is_reference {
              process_env.insert(key, secret.clone());
            }
          }
        }
      }
      Err(infisical_err) => {
        let error = RowError::Structured(EnvryptError::infisical_resolution_failed(
          &infisical_err.message(),
        ));
        if options.strict {
          return Err(error);
        }
        logger.error(
          &error
            .message_with_help()
            .unwrap_or_else(|| error.catch_message()),
        );
        last_error = Some(error);
      }
    }
  }

  // Opt-in `pass` (Unix password store) `pass://` resolution — same fail-closed
  // shape over the merged map, running only when `pass_exec` is threaded. Resolved
  // secrets mirror into `process_env` (only overwriting keys still holding
  // `pass://`).
  if let Some(pass_exec) = options.pass_exec {
    let pass_keys: Vec<String> = parsed_all
      .iter()
      .filter(|(_, value)| is_pass_reference(value))
      .map(|(key, _)| key.clone())
      .collect();
    match resolve_pass_references(&mut parsed_all, pass_exec, options.pass_timeout) {
      Ok(()) => {
        for key in pass_keys {
          if let Some(secret) = parsed_all.get(&key) {
            let injected_is_reference = process_env
              .get(&key)
              .is_some_and(|value| is_pass_reference(value));
            if injected_is_reference {
              process_env.insert(key, secret.clone());
            }
          }
        }
      }
      Err(pass_err) => {
        let error = RowError::Structured(EnvryptError::pass_resolution_failed(&pass_err.message()));
        if options.strict {
          return Err(error);
        }
        logger.error(
          &error
            .message_with_help()
            .unwrap_or_else(|| error.catch_message()),
        );
        last_error = Some(error);
      }
    }
  }

  // Opt-in HashiCorp Vault `vault://` resolution — same fail-closed shape over the
  // merged map, running only when `vault_exec` is threaded. Resolved secrets
  // mirror into `process_env` (only overwriting keys still holding `vault://`).
  if let Some(vault_exec) = options.vault_exec {
    let vault_keys: Vec<String> = parsed_all
      .iter()
      .filter(|(_, value)| is_vault_reference(value))
      .map(|(key, _)| key.clone())
      .collect();
    match resolve_vault_references(&mut parsed_all, vault_exec, options.vault_timeout) {
      Ok(()) => {
        for key in vault_keys {
          if let Some(secret) = parsed_all.get(&key) {
            let injected_is_reference = process_env
              .get(&key)
              .is_some_and(|value| is_vault_reference(value));
            if injected_is_reference {
              process_env.insert(key, secret.clone());
            }
          }
        }
      }
      Err(vault_err) => {
        let error =
          RowError::Structured(EnvryptError::vault_resolution_failed(&vault_err.message()));
        if options.strict {
          return Err(error);
        }
        logger.error(
          &error
            .message_with_help()
            .unwrap_or_else(|| error.catch_message()),
        );
        last_error = Some(error);
      }
    }
  }

  Ok(ConfigResult {
    parsed: parsed_all,
    error: last_error,
  })
}

/// Renders the parsed map for debug logging: a compact, insertion-ordered JSON
/// object, or the literal `undefined` on error rows (`┆ undefined`). serde_json
/// with `preserve_order` matches `JSON.stringify`'s output byte-for-byte.
pub fn debug_parsed_line(parsed: Option<&IndexMap<String, String>>) -> String {
  match parsed {
    None => "undefined".to_string(),
    Some(map) => {
      let mut json = serde_json::Map::new();
      for (k, v) in map {
        json.insert(k.clone(), serde_json::Value::String(v.clone()));
      }
      serde_json::Value::Object(json).to_string()
    }
  }
}

/// Counts the distinct keys injected across all rows.
pub fn unique_injected_count(processed_envs: &[ProcessedEnv]) -> usize {
  let mut keys = IndexSet::new();
  for processed_env in processed_envs {
    for key in processed_env.injected.keys() {
      keys.insert(key);
    }
  }
  keys.len()
}

#[cfg(test)]
mod test_helpers {
  use super::*;

  pub(super) fn env_map(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    pairs
      .iter()
      .map(|(k, v)| (k.to_string(), v.to_string()))
      .collect()
  }

  pub(super) fn fixture(rel: &str) -> String {
    test_support::fixture_path(rel)
      .to_string_lossy()
      .into_owned()
  }

  pub(super) fn quiet_logger() -> (test_support::LoggerCapture, Logger) {
    let cap = test_support::LoggerCapture::new();
    let logger = Logger::new(
      Box::new(cap.stdout_writer()),
      Box::new(cap.stderr_writer()),
      1,
    );
    (cap, logger)
  }
}

#[cfg(test)]
mod monorepo_config_test {
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
      cap
        .stderr()
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
}

#[cfg(test)]
mod config_test {
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
}

#[cfg(test)]
mod resolution_helpers_test {
  // Pins for default selection, file-path preparation, and lexical paths.
  use super::test_helpers::*;
  use super::*;

  #[test]
  fn determine_defaults_to_dotenv_file() {
    let pe = env_map(&[]);
    assert_eq!(determine(vec![], &pe, &KeyNaming::default()), vec![".env"]);
  }

  #[test]
  fn determine_guesses_filenames_from_private_key_names() {
    // ENVRYPT_PRIVATE_KEY_X_Y → .env.x.y (underscores → dots, lowercased);
    // multiple keys → multiple defaults, in env order.
    let pe = env_map(&[
      ("ENVRYPT_PRIVATE_KEY_PRODUCTION", "abc"),
      ("ENVRYPT_PRIVATE_KEY", "def"),
    ]);
    assert_eq!(
      determine(vec![], &pe, &KeyNaming::default()),
      vec![".env.production", ".env",]
    );
  }

  #[test]
  fn determine_returns_paths_unchanged_when_a_file_is_specified() {
    let pe = env_map(&[("ENVRYPT_PRIVATE_KEY", "abc")]);
    let paths = vec![".env.custom".to_string()];
    assert_eq!(determine(paths.clone(), &pe, &KeyNaming::default()), paths);
  }

  #[test]
  fn build_env_file_paths_prepends_convention_files() {
    // Conventions first, then explicit file paths.
    let global = env_map(&[]);
    let cwd = std::env::temp_dir();
    let out = build_env_file_paths(&[".env2".to_string()], Some("flow"), &global, &cwd).unwrap();
    assert_eq!(
      out,
      vec![
        ".env.development.local",
        ".env.development",
        ".env.local",
        ".env",
        ".env.defaults",
        ".env2",
      ]
    );
  }

  #[test]
  fn build_env_file_paths_resolves_directory_to_dotenv() {
    // An existing directory becomes `<dir>/.env` in its original relative
    // form (banner: `⟐ injected env (1) from sub/.env`).
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let global = env_map(&[]);
    let out = build_env_file_paths(&["sub".to_string()], None, &global, dir.path()).unwrap();
    assert_eq!(out, vec!["sub/.env"]);
  }

  #[test]
  fn resolve_directory_filepath_normalizes_like_node_path_join() {
    // The join is Node's path.join, which normalizes. Banner strings:
    //   `run -f . …`      → `⟐ injected env (2) from .env`      (NOT ./.env)
    //   `run -f ./ …`     → `⟐ injected env (2) from .env`
    //   `run -f sub/. …`  → `… from sub/.env`                   (NOT sub/./.env)
    //   `run -f sub …`    → `… from sub/.env`
    //   `run -f sub/ …`   → `… from sub/.env`
    //   `run -f .. …`     → `… from ../.env`
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let cwd = dir.path();
    let cases: &[(&str, &str)] = &[
      (".", ".env"),
      ("./", ".env"),
      (".//", ".env"),
      ("sub", "sub/.env"),
      ("sub/", "sub/.env"),
      ("sub/.", "sub/.env"),
      ("./sub", "sub/.env"),
      ("..", "../.env"),
    ];
    for (input, expected) in cases {
      assert_eq!(
        resolve_directory_filepath(input, ".env", cwd),
        *expected,
        "resolveDirectoryFilepath({input:?}, \".env\")"
      );
    }
    // Same class through the -fk resolution path.
    assert_eq!(
      resolve_env_keys_file(Some(vec![".".to_string(), "sub/.".to_string()]), cwd),
      Some(vec![".env.keys".to_string(), "sub/.env.keys".to_string()])
    );
    // Non-directories still pass through UNCHANGED (no normalization).
    assert_eq!(
      resolve_directory_filepath("./missing", ".env", cwd),
      "./missing"
    );
    assert_eq!(
      resolve_directory_filepath("sub/./.env", ".env", cwd),
      "sub/./.env"
    );
  }

  #[test]
  fn build_env_file_paths_directory_with_convention_expands_into_directory() {
    // A directory arg plus a convention expands the convention list into that
    // directory (and suppresses the global prepend).
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let global = env_map(&[]);
    let out =
      build_env_file_paths(&["sub".to_string()], Some("nextjs"), &global, dir.path()).unwrap();
    assert_eq!(
      out,
      vec![
        "sub/.env.development.local",
        "sub/.env.local",
        "sub/.env.development",
        "sub/.env",
      ]
    );
  }

  #[test]
  fn invalid_convention_propagates() {
    let global = env_map(&[]);
    let err = build_env_file_paths(&[], Some("bogus"), &global, Path::new("/tmp")).unwrap_err();
    assert_eq!(err.code(), Some("INVALID_CONVENTION"));
  }

  #[test]
  fn expand_home_paths_expands_home() {
    let paths = vec!["~/.env".to_string(), ".env".to_string()];
    let out = expand_home_paths(Some(&paths), Some(Path::new("/home/<user>")));
    assert_eq!(
      out,
      vec!["/home/<user>/.env".to_string(), ".env".to_string()]
    );
  }

  #[test]
  fn resolve_lexical_normalizes_without_fs() {
    assert_eq!(
      resolve_lexical(Path::new("/a/b"), "../c/./d"),
      PathBuf::from("/a/c/d")
    );
    assert_eq!(
      resolve_lexical(Path::new("/a"), "/x/../y"),
      PathBuf::from("/y")
    );
  }
}
