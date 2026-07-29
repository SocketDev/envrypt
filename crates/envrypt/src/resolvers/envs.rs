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
  /// Working directory for path resolution. `None` inherits the process cwd.
  pub cwd: Option<PathBuf>,
  /// The key-identifier naming (default `ENVRYPT_`).
  pub naming: KeyNaming,
  /// The byte budget for one expanded value. `None` →
  /// [`crate::parse::expand::DEFAULT_MAX_EXPAND_OUTPUT_BYTES`].
  pub max_expand_output_bytes: Option<usize>,
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
fn parse_row(
  src: &str,
  fk: Vec<PathBuf>,
  options: &EnvsOptions,
  process_env: &mut IndexMap<String, String>,
  row: &mut ProcessedEnv,
  on_status: &mut dyn FnMut(&str),
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
  parse_options.naming = &options.naming;
  if let Some(budget) = options.max_expand_output_bytes {
    parse_options.max_expand_output_bytes = budget;
  }
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

  parse_row(&src, fk, options, process_env, &mut row, on_status);
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

mod config;
pub use config::{config, ConfigOptions, ConfigResult};

#[cfg(test)]
mod config_test;
#[cfg(test)]
mod monorepo_config_test;
#[cfg(test)]
mod resolution_helpers_test;
#[cfg(test)]
mod test_helpers;
