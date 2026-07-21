//! The curated, hard-to-misuse public API. Everything an embedding app needs
//! ([`load`], [`config`], [`LoadOptions`], [`KeyPolicy`], [`KeyResolver`],
//! [`Loaded`]) is re-exported at the crate root. The internal engine
//! (parse / keyring / providers / resolvers) stays `#[doc(hidden)]`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use indexmap::IndexMap;
use zeroize::Zeroize;

use crate::conventions::keynames::KeyNaming;
use crate::keyring::Ring;
use crate::output::logger::Logger;
use crate::providers::{
  build_providers, ci_vendor_detected_from_env, KeyProvider, ProviderError, ProviderGating,
};
use crate::resolvers::envs::{config as internal_config, ConfigOptions, RowError};

// ---- re-exported safe surface (no Ring/KeyProvider/IndexMap) -----------------------

/// The coded error carried by the value-level [`decrypt`] read path.
pub use crate::crypto::CryptoError;
/// Value-level crypto in the native v3 format (`docs/envrypt/crypto-v3.md`):
/// [`encrypt`] seals a plaintext to an X25519 public key as `encrypted:`, bound to
/// its variable name; [`decrypt`] opens it with the private key and also reads the
/// frozen v1 layout, so existing values keep decrypting. [`keypair_v3`] mints the
/// X25519 recipient identity; every [`encrypt`] failure is the opaque [`V3Error`].
/// envrypt writes v3 exclusively; this curated surface is the write path.
pub use crate::crypto_v3::{
  decrypt_entry as decrypt, encrypt_v3 as encrypt, keypair_v3, V3Error, V3Keypair,
};
/// The envrypt error type. Carries the error code + `fix:` help for crypto/parse
/// failures.
pub use crate::errors::EnvryptError;

// ---- diagnostics -------------------------------------------------------------------

/// The severity of a [`Diagnostic`] surfaced through [`LoadOptions::on_diagnostic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticLevel {
  /// An error the resolver logged (a decrypt/parse/read failure in non-strict mode).
  Error,
  /// Informational output (the injected-env summary line).
  Info,
}

/// A diagnostic message emitted during resolution. Routed to an opt-in callback
/// instead of stderr, so the library stays quiet by default.
#[derive(Debug, Clone)]
pub struct Diagnostic {
  /// The severity.
  pub level: DiagnosticLevel,
  /// The rendered message (no trailing newline, no ANSI color).
  pub message: String,
}

// ---- errors ------------------------------------------------------------------------

/// The error returned by [`load`] / [`config`]. Under the default strict mode, any
/// unresolved or undecryptable value surfaces here; an undecryptable value is never
/// an `Ok` carrying `encrypted:` ciphertext.
#[derive(Debug, Clone)]
pub struct LoadError {
  code: Option<String>,
  message: String,
}

impl LoadError {
  /// The error code (e.g. `DECRYPTION_FAILED`, `MISSING_ENV_FILE`), if any.
  pub fn code(&self) -> Option<&str> {
    self.code.as_deref()
  }

  /// The human-readable message (with the `fix:` help where available).
  pub fn message(&self) -> &str {
    &self.message
  }
}

impl std::fmt::Display for LoadError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.message)
  }
}

impl std::error::Error for LoadError {}

impl From<RowError> for LoadError {
  fn from(e: RowError) -> Self {
    LoadError {
      code: {
        let c = e.code();
        if c.is_empty() {
          None
        } else {
          Some(c.to_string())
        }
      },
      message: e.catch_message(),
    }
  }
}

// ---- provider seam (narrow, safe) --------------------------------------------------

/// A custom key source. The whole public surface is `resolve(public_key_hex) ->
/// Option<private_key_hex>`; the internal two-phase `Ring`/`KeyProvider` protocol stays
/// crate-private, so envrypt's semver is not coupled to `indexmap`.
pub trait KeyResolver {
  /// Resolve the private key (hex) for a compressed public key (hex), or `None`.
  fn resolve(&self, public_key_hex: &str) -> Option<String>;
}

/// Adapter: wrap a public [`KeyResolver`] into the private `KeyProvider` machinery.
struct ResolverProvider(Arc<dyn KeyResolver>);

impl KeyProvider for ResolverProvider {
  fn lookup(&self, ring: &mut Ring, _on_status: &mut dyn FnMut(&str)) -> Result<(), ProviderError> {
    let blanks: Vec<String> = ring
      .iter()
      .filter(|(_, v)| v.is_empty())
      .map(|(k, _)| k.clone())
      .collect();
    for public_key in blanks {
      if let Some(private_key) = self.0.resolve(&public_key) {
        if !private_key.is_empty() {
          ring.insert(public_key, private_key);
        }
      }
    }
    Ok(())
  }
}

/// The private-key resolution policy. The safe default reads only process
/// environment and `.env.keys`; direct OS-keychain reads require an explicit
/// opt-in because they return secret bytes to the embedding process.
#[derive(Default)]
pub enum KeyPolicy {
  /// env → `.env.keys` only. This is the default. A Sockeye-approved child
  /// receives an `envrypt-v1` descriptor through Sockeye and resolves it in this
  /// mode without a second OS credential read.
  #[default]
  EnvOnly,
  /// env → `.env.keys` → OS keychain (keychain auto-skips under CI).
  ///
  /// This is for non-agent embedding applications that deliberately accept the
  /// host OS keychain's access policy. It is not a substitute for Sockeye.
  SystemKeychain,
  /// Replace the phase-2 provider chain with custom [`KeyResolver`]s (consulted after
  /// the file+env phase, in order). `Arc` so the policy is callable through
  /// `config(&LoadOptions)`.
  Custom(Vec<Arc<dyn KeyResolver>>),
}

impl KeyPolicy {
  /// Build the phase-2 provider chain for this policy.
  fn build(&self, timeout: Duration) -> Vec<Box<dyn KeyProvider>> {
    match self {
      KeyPolicy::EnvOnly => Vec::new(),
      KeyPolicy::SystemKeychain => build_providers(
        &ProviderGating::default(),
        node_platform(),
        ci_vendor_detected_from_env(),
        timeout,
      ),
      KeyPolicy::Custom(resolvers) => resolvers
        .iter()
        .map(|r| Box::new(ResolverProvider(r.clone())) as Box<dyn KeyProvider>)
        .collect(),
    }
  }
}

/// Node `process.platform` for the current build target (macOS→`darwin`, Windows→
/// `win32`, else the `std::env::consts::OS` string). Drives the keychain gate.
fn node_platform() -> &'static str {
  match std::env::consts::OS {
    "macos" => "darwin",
    "windows" => "win32",
    other => other,
  }
}

// ---- options -----------------------------------------------------------------------

/// Options for [`config`]. Every field has a safe default (see [`LoadOptions::default`]);
/// the zero-config [`load`] uses them verbatim.
pub struct LoadOptions {
  /// The `.env` file paths to read. `None` → `[".env"]`.
  pub path: Option<Vec<PathBuf>>,
  /// Explicit `.env.keys` file paths. `None` → sibling `.env.keys` discovery.
  pub env_keys_file: Option<Vec<PathBuf>>,
  /// A dotenv convention name (e.g. `nextjs`, `flow`) to expand into a file list.
  pub convention: Option<String>,
  /// Let `.env` values override values already present in `std::env`.
  pub overload: bool,
  /// **Strict (DEFAULT `true`).** An unresolved/undecryptable value → `Err(LoadError)`,
  /// never an `Ok` carrying ciphertext. Set `false` for best-effort: undecryptable
  /// values are then kept as ciphertext in the map and reported via
  /// [`Loaded::errors`].
  pub strict: bool,
  /// Error codes to ignore (e.g. `MISSING_ENV_FILE`).
  pub ignore: Vec<String>,
  /// The private-key resolution policy.
  pub policy: KeyPolicy,
  /// **Injection (DEFAULT `false`).** When `true`, [`config`] also writes the resolved
  /// values into `std::env`. This mutates global process state: **call it before
  /// spawning threads** — concurrent `set_var`/`getenv` is undefined behavior, and
  /// `std::env::set_var` becomes `unsafe` under edition 2024 (this crate is edition
  /// 2021 / MSRV 1.80). The default `false` returns the map without touching
  /// `std::env`.
  pub inject: bool,
  /// The bounded timeout for each keychain subprocess. `None` → the crate default
  /// (~2 s). On timeout the keychain yields nothing and resolution falls through to
  /// the env path.
  pub keychain_timeout: Option<Duration>,
  /// An optional diagnostics callback. Use interior mutability (e.g. a `Mutex`)
  /// for a stateful sink.
  pub on_diagnostic: Option<Box<dyn Fn(Diagnostic)>>,
  /// The key-identifier prefix. `None` → `ENVRYPT_` (driving `ENVRYPT_PRIVATE_KEY`
  /// and `ENVRYPT_PUBLIC_KEY`). Set another prefix to read differently named keys.
  pub key_prefix: Option<String>,
  /// An explicit private-key variable name (overrides the prefix-derived name).
  pub private_key_var: Option<String>,
  /// An explicit public-key variable name (overrides the prefix-derived name).
  pub public_key_var: Option<String>,
  /// Opt-in 1Password `op://` secret resolution. When `true`, every resolved
  /// value of the form `op://<vault>/<item>/<field>` is replaced with the secret
  /// read from the 1Password CLI (`op read`), and the secret is injected in
  /// place of the reference. Default `false`: an `op://` string loads verbatim,
  /// so nothing shells out unless you ask. Fail-closed — a reference that can't
  /// resolve is an error (`OP_RESOLUTION_FAILED`), never a silent pass-through.
  pub resolve_op_references: bool,
  /// The bounded timeout for each `op read` when `resolve_op_references` is set.
  /// `None` → the crate default (~10 s, room for a one-time device-auth prompt).
  pub op_timeout: Option<Duration>,
  /// Opt-in Bitwarden `bw://` secret resolution. When `true`, every resolved
  /// value of the form `bw://<item-uuid>/<field>` is replaced with the secret
  /// read from the Bitwarden CLI (`bw get`, reading the unlocked `BW_SESSION`).
  /// Default `false`: a `bw://` string loads verbatim. Fail-closed — a reference
  /// that can't resolve is an error (`BW_RESOLUTION_FAILED`), never a silent
  /// pass-through.
  pub resolve_bw_references: bool,
  /// The bounded timeout for each `bw get` when `resolve_bw_references` is set.
  /// `None` → the crate default (~10 s).
  pub bw_timeout: Option<Duration>,
  /// Opt-in AWS Secrets Manager `aws://` secret resolution. When `true`, every
  /// resolved value of the form `aws://<secret-id>` is replaced with the secret
  /// read from the AWS CLI (`aws secretsmanager get-secret-value`, using the
  /// standard credential chain). Default `false`: an `aws://` string loads
  /// verbatim. Fail-closed — a reference that can't resolve is an error
  /// (`AWS_RESOLUTION_FAILED`), never a silent pass-through.
  pub resolve_aws_references: bool,
  /// The bounded timeout for each `aws secretsmanager get-secret-value` when
  /// `resolve_aws_references` is set. `None` → the crate default (~10 s).
  pub aws_timeout: Option<Duration>,
  /// Opt-in Azure Key Vault `azure://` secret resolution. When `true`, every
  /// resolved value of the form `azure://<vault>/<name>` is replaced with the
  /// secret read from the Azure CLI (`az keyvault secret show`, using the `az
  /// login` session). Default `false`: an `azure://` string loads verbatim.
  /// Fail-closed — a reference that can't resolve is an error
  /// (`AZURE_RESOLUTION_FAILED`), never a silent pass-through.
  pub resolve_azure_references: bool,
  /// The bounded timeout for each `az keyvault secret show` when
  /// `resolve_azure_references` is set. `None` → the crate default (~10 s).
  pub azure_timeout: Option<Duration>,
  /// Opt-in Doppler `doppler://` secret resolution. When `true`, every resolved
  /// value of the form `doppler://<name>` is replaced with the secret read from
  /// the Doppler CLI (`doppler secrets get`, using the `doppler login` session or
  /// a `DOPPLER_TOKEN`). Default `false`: a `doppler://` string loads verbatim.
  /// Fail-closed — a reference that can't resolve is an error
  /// (`DOPPLER_RESOLUTION_FAILED`), never a silent pass-through.
  pub resolve_doppler_references: bool,
  /// The bounded timeout for each `doppler secrets get` when
  /// `resolve_doppler_references` is set. `None` → the crate default (~10 s).
  pub doppler_timeout: Option<Duration>,
  /// Opt-in GCP Secret Manager `gcp://` secret resolution. When `true`, every
  /// resolved value of the form `gcp://<name>` is replaced with the secret read
  /// from the `gcloud` CLI (`gcloud secrets versions access`, using `gcloud auth`
  /// credentials). Default `false`: a `gcp://` string loads verbatim.
  /// Fail-closed — a reference that can't resolve is an error
  /// (`GCP_RESOLUTION_FAILED`), never a silent pass-through.
  pub resolve_gcp_references: bool,
  /// The bounded timeout for each `gcloud secrets versions access` when
  /// `resolve_gcp_references` is set. `None` → the crate default (~10 s).
  pub gcp_timeout: Option<Duration>,
  /// Opt-in Infisical `infisical://` secret resolution. When `true`, every
  /// resolved value of the form `infisical://<name>` is replaced with the secret
  /// read from the Infisical CLI (`infisical secrets get`, using the `infisical
  /// login` session or an `INFISICAL_TOKEN`). Default `false`: an `infisical://`
  /// string loads verbatim. Fail-closed — a reference that can't resolve is an
  /// error (`INFISICAL_RESOLUTION_FAILED`), never a silent pass-through.
  pub resolve_infisical_references: bool,
  /// The bounded timeout for each `infisical secrets get` when
  /// `resolve_infisical_references` is set. `None` → the crate default (~10 s).
  pub infisical_timeout: Option<Duration>,
  /// Opt-in `pass` (Unix password store) `pass://` secret resolution. When
  /// `true`, every resolved value of the form `pass://<path>` is replaced with the
  /// secret read from the `pass` CLI (`pass show`, decrypting via `gpg-agent`).
  /// Default `false`: a `pass://` string loads verbatim. Fail-closed — a
  /// reference that can't resolve is an error (`PASS_RESOLUTION_FAILED`), never a
  /// silent pass-through.
  pub resolve_pass_references: bool,
  /// The bounded timeout for each `pass show` when `resolve_pass_references` is
  /// set. `None` → the crate default (~10 s).
  pub pass_timeout: Option<Duration>,
  /// Opt-in HashiCorp Vault `vault://` secret resolution. When `true`, every
  /// resolved value of the form `vault://<path>#<field>` is replaced with the
  /// secret read from the Vault CLI (`vault kv get`, using `VAULT_ADDR` +
  /// `VAULT_TOKEN`). Default `false`: a `vault://` string loads verbatim.
  /// Fail-closed — a reference that can't resolve is an error
  /// (`VAULT_RESOLUTION_FAILED`), never a silent pass-through.
  pub resolve_vault_references: bool,
  /// The bounded timeout for each `vault kv get` when `resolve_vault_references`
  /// is set. `None` → the crate default (~10 s).
  pub vault_timeout: Option<Duration>,
}

impl Default for LoadOptions {
  fn default() -> Self {
    LoadOptions {
      path: None,
      env_keys_file: None,
      convention: None,
      overload: false,
      strict: true,
      ignore: Vec::new(),
      policy: KeyPolicy::EnvOnly,
      inject: false,
      keychain_timeout: None,
      on_diagnostic: None,
      key_prefix: None,
      private_key_var: None,
      public_key_var: None,
      resolve_op_references: false,
      op_timeout: None,
      resolve_bw_references: false,
      bw_timeout: None,
      resolve_aws_references: false,
      aws_timeout: None,
      resolve_azure_references: false,
      azure_timeout: None,
      resolve_doppler_references: false,
      doppler_timeout: None,
      resolve_gcp_references: false,
      gcp_timeout: None,
      resolve_infisical_references: false,
      infisical_timeout: None,
      resolve_pass_references: false,
      pass_timeout: None,
      resolve_vault_references: false,
      vault_timeout: None,
    }
  }
}

impl LoadOptions {
  /// Derive the internal [`KeyNaming`] from the prefix and explicit-var config.
  fn key_naming(&self) -> KeyNaming {
    let mut naming = match &self.key_prefix {
      Some(prefix) => KeyNaming::from_prefix(prefix),
      None => KeyNaming::default(),
    };
    naming.private_key_var = self.private_key_var.clone();
    naming.public_key_var = self.public_key_var.clone();
    naming
  }
}

// ---- result ------------------------------------------------------------------------

/// The resolved environment returned by [`load`] / [`config`]. Exposes accessors,
/// never a public `indexmap` type; carries no `error` field that `?` bypasses, since
/// strict-mode failures are an `Err(LoadError)`.
pub struct Loaded {
  map: IndexMap<String, String>,
  errors: Vec<String>,
}

// Redacting `Debug` — never prints resolved values (they may be secrets).
impl std::fmt::Debug for Loaded {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Loaded")
      .field("keys", &self.map.len())
      .field("errors", &self.errors.len())
      .finish()
  }
}

impl Loaded {
  /// The value for `key`, if present.
  pub fn get(&self, key: &str) -> Option<&str> {
    self.map.get(key).map(String::as_str)
  }

  /// Iterate the `(key, value)` pairs in insertion order.
  pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
    self.map.iter().map(|(k, v)| (k.as_str(), v.as_str()))
  }

  /// The number of resolved keys.
  pub fn len(&self) -> usize {
    self.map.len()
  }

  /// Whether no keys were resolved.
  pub fn is_empty(&self) -> bool {
    self.map.is_empty()
  }

  /// Consume into a sorted `BTreeMap` (e.g. to feed `Command::envs`).
  pub fn into_env_map(self) -> BTreeMap<String, String> {
    self.map.into_iter().collect()
  }

  /// The best-effort errors collected under `strict = false` (empty in strict mode,
  /// where the same conditions are an `Err(LoadError)` instead).
  pub fn errors(&self) -> &[String] {
    &self.errors
  }
}

// ---- entry points ------------------------------------------------------------------

/// Read `.env`, resolve the private key (env → `.env.keys`),
/// decrypt `encrypted:` values, and return the map. Strict, and does **not** mutate
/// `std::env`.
///
/// ```no_run
/// let loaded = envrypt::load()?;
/// if let Some(token) = loaded.get("STRIPE_SECRET") {
///     // use the decrypted token
///     let _ = token;
/// }
/// # Ok::<(), envrypt::LoadError>(())
/// ```
pub fn load() -> Result<Loaded, LoadError> {
  config(&LoadOptions::default())
}

/// Like [`load`], with explicit [`LoadOptions`].
pub fn config(opts: &LoadOptions) -> Result<Loaded, LoadError> {
  // The real process env is both the convention source (DOTENV_ENV/NODE_ENV) and the
  // decrypt-then-inject TARGET (pre-existing values take precedence, dotenv semantics).
  let global_env: IndexMap<String, String> = std::env::vars().collect();
  let mut process_env = global_env.clone();

  let naming = opts.key_naming();
  let timeout = opts
    .keychain_timeout
    .unwrap_or(crate::providers::keychain::DEFAULT_KEYCHAIN_TIMEOUT);
  let providers = opts.policy.build(timeout);
  let inherited_private_key =
    crate::sockeye::read_inherited_private_key().map_err(|message| LoadError {
      code: None,
      message,
    })?;
  if let Some(private_key) = inherited_private_key.as_ref() {
    process_env.insert(
      crate::sockeye::CREDENTIAL_NAME.to_string(),
      private_key.to_string(),
    );
  }

  let out_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
  let err_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
  let mut logger = Logger::new(
    Box::new(SharedWriter(out_buf.clone())),
    Box::new(SharedWriter(err_buf.clone())),
    1, // color depth 1 → no ANSI in captured diagnostics
  );

  // Opt-in `op://` resolution: thread the production [`SystemExec`] only when the
  // caller enabled it, so `op` is never spawned by default.
  let op_system_exec = crate::providers::keychain::SystemExec;
  let op_exec: Option<&dyn crate::providers::keychain::Exec> = if opts.resolve_op_references {
    Some(&op_system_exec)
  } else {
    None
  };
  let op_timeout = opts
    .op_timeout
    .unwrap_or(crate::resolvers::onepassword::DEFAULT_OP_TIMEOUT);

  // Opt-in `bw://` resolution: thread the production [`SystemExec`] only when the
  // caller enabled it, so `bw` is never spawned by default.
  let bw_system_exec = crate::providers::keychain::SystemExec;
  let bw_exec: Option<&dyn crate::providers::keychain::Exec> = if opts.resolve_bw_references {
    Some(&bw_system_exec)
  } else {
    None
  };
  let bw_timeout = opts
    .bw_timeout
    .unwrap_or(crate::resolvers::bitwarden::DEFAULT_BW_TIMEOUT);

  // Opt-in `aws://` resolution: thread the production [`SystemExec`] only when the
  // caller enabled it, so `aws` is never spawned by default.
  let aws_system_exec = crate::providers::keychain::SystemExec;
  let aws_exec: Option<&dyn crate::providers::keychain::Exec> = if opts.resolve_aws_references {
    Some(&aws_system_exec)
  } else {
    None
  };
  let aws_timeout = opts
    .aws_timeout
    .unwrap_or(crate::resolvers::aws::DEFAULT_AWS_TIMEOUT);

  // Opt-in `azure://` resolution: thread the production [`SystemExec`] only when
  // the caller enabled it, so `az` is never spawned by default.
  let azure_system_exec = crate::providers::keychain::SystemExec;
  let azure_exec: Option<&dyn crate::providers::keychain::Exec> = if opts.resolve_azure_references {
    Some(&azure_system_exec)
  } else {
    None
  };
  let azure_timeout = opts
    .azure_timeout
    .unwrap_or(crate::resolvers::azure::DEFAULT_AZURE_TIMEOUT);

  // Opt-in `doppler://` resolution: thread the production [`SystemExec`] only when
  // the caller enabled it, so `doppler` is never spawned by default.
  let doppler_system_exec = crate::providers::keychain::SystemExec;
  let doppler_exec: Option<&dyn crate::providers::keychain::Exec> =
    if opts.resolve_doppler_references {
      Some(&doppler_system_exec)
    } else {
      None
    };
  let doppler_timeout = opts
    .doppler_timeout
    .unwrap_or(crate::resolvers::doppler::DEFAULT_DOPPLER_TIMEOUT);

  // Opt-in `gcp://` resolution: thread the production [`SystemExec`] only when the
  // caller enabled it, so `gcloud` is never spawned by default.
  let gcp_system_exec = crate::providers::keychain::SystemExec;
  let gcp_exec: Option<&dyn crate::providers::keychain::Exec> = if opts.resolve_gcp_references {
    Some(&gcp_system_exec)
  } else {
    None
  };
  let gcp_timeout = opts
    .gcp_timeout
    .unwrap_or(crate::resolvers::gcp::DEFAULT_GCP_TIMEOUT);

  // Opt-in `infisical://` resolution: thread the production [`SystemExec`] only
  // when the caller enabled it, so `infisical` is never spawned by default.
  let infisical_system_exec = crate::providers::keychain::SystemExec;
  let infisical_exec: Option<&dyn crate::providers::keychain::Exec> =
    if opts.resolve_infisical_references {
      Some(&infisical_system_exec)
    } else {
      None
    };
  let infisical_timeout = opts
    .infisical_timeout
    .unwrap_or(crate::resolvers::infisical::DEFAULT_INFISICAL_TIMEOUT);

  // Opt-in `pass://` resolution: thread the production [`SystemExec`] only when
  // the caller enabled it, so `pass` is never spawned by default.
  let pass_system_exec = crate::providers::keychain::SystemExec;
  let pass_exec: Option<&dyn crate::providers::keychain::Exec> = if opts.resolve_pass_references {
    Some(&pass_system_exec)
  } else {
    None
  };
  let pass_timeout = opts
    .pass_timeout
    .unwrap_or(crate::resolvers::pass::DEFAULT_PASS_TIMEOUT);

  // Opt-in `vault://` resolution: thread the production [`SystemExec`] only when
  // the caller enabled it, so `vault` is never spawned by default.
  let vault_system_exec = crate::providers::keychain::SystemExec;
  let vault_exec: Option<&dyn crate::providers::keychain::Exec> = if opts.resolve_vault_references {
    Some(&vault_system_exec)
  } else {
    None
  };
  let vault_timeout = opts
    .vault_timeout
    .unwrap_or(crate::resolvers::vault::DEFAULT_VAULT_TIMEOUT);

  let internal = ConfigOptions {
    path: opts
      .path
      .as_ref()
      .map(|paths| paths.iter().map(|p| path_to_string(p)).collect()),
    overload: opts.overload,
    strict: opts.strict,
    ignore: opts.ignore.clone(),
    env_keys_file: opts
      .env_keys_file
      .as_ref()
      .map(|paths| paths.iter().map(|p| path_to_string(p)).collect()),
    convention: opts.convention.clone(),
    providers: &providers,
    global_env,
    home_dir: None,
    cwd: None,
    naming,
    op_exec,
    op_timeout,
    bw_exec,
    bw_timeout,
    aws_exec,
    aws_timeout,
    azure_exec,
    azure_timeout,
    doppler_exec,
    doppler_timeout,
    gcp_exec,
    gcp_timeout,
    infisical_exec,
    infisical_timeout,
    pass_exec,
    pass_timeout,
    vault_exec,
    vault_timeout,
  };

  let result = internal_config(&internal, &mut process_env, &mut logger);
  if let Some(mut private_key) = process_env.shift_remove(crate::sockeye::CREDENTIAL_NAME) {
    private_key.zeroize();
  }

  // Route the captured logger output to the diagnostics callback (if any).
  if let Some(cb) = &opts.on_diagnostic {
    forward(&err_buf, DiagnosticLevel::Error, cb);
    forward(&out_buf, DiagnosticLevel::Info, cb);
  }

  let config_result = result?; // strict: a resolver error is already an Err here

  // Opt-in global injection (off by default; call before threads).
  if opts.inject {
    for (key, value) in &config_result.parsed {
      std::env::set_var(key, value);
    }
  }

  let errors = config_result
    .error
    .as_ref()
    .map(|e| vec![e.catch_message()])
    .unwrap_or_default();

  Ok(Loaded {
    map: config_result.parsed,
    errors,
  })
}

// ---- internal plumbing -------------------------------------------------------------

fn path_to_string(p: &std::path::Path) -> String {
  p.to_string_lossy().into_owned()
}

/// A `Write` sink that appends into a shared buffer (Logger output capture).
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
  fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    if let Ok(mut guard) = self.0.lock() {
      guard.extend_from_slice(buf);
    }
    Ok(buf.len())
  }
  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

fn forward(buf: &Arc<Mutex<Vec<u8>>>, level: DiagnosticLevel, cb: &dyn Fn(Diagnostic)) {
  let bytes = match buf.lock() {
    Ok(g) => g.clone(),
    Err(_) => return,
  };
  let text = String::from_utf8_lossy(&bytes);
  for line in text.lines() {
    if line.is_empty() {
      continue;
    }
    cb(Diagnostic {
      level,
      message: line.to_string(),
    });
  }
}
