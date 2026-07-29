//! `config()`: builds the env-file list, runs the resolver rows, resolves
//! provider references, and merges the result. Split from `envs.rs` for the
//! max-file-lines doctrine; pure code motion.

use super::*;

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
  /// The byte budget for one expanded value. `None` →
  /// [`crate::parse::expand::DEFAULT_MAX_EXPAND_OUTPUT_BYTES`].
  pub max_expand_output_bytes: Option<usize>,
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
      max_expand_output_bytes: None,
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
    max_expand_output_bytes: options.max_expand_output_bytes,
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
