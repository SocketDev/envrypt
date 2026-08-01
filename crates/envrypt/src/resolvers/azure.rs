//! Azure Key Vault `azure://` secret-reference resolution (opt-in, fail-closed).
//!
//! A resolved env value of the form `azure://<vault>/<name>` is replaced with the
//! secret the Azure CLI prints for it (`az keyvault secret show --vault-name
//! <vault> --name <name> --query value -o tsv`). The `<vault>` is the Key Vault
//! name and `<name>` is the secret's name, mirroring the familiar
//! `API_KEY="azure://my-vault/db-password"` shape, the companion to
//! [`super::bitwarden`].
//!
//! Runs ONLY when the caller opts in (an `Exec` is threaded through
//! [`crate::resolvers::envs::ConfigOptions::azure_exec`]); a stored `azure://`
//! string is inert by default, so nothing shells out unless the consumer asked
//! for it.
//!
//! SESSION — `az` reads its session from `az login` in the process environment,
//! which the spawned child inherits from this process. An unauthenticated CLI
//! exits non-zero, which surfaces as a fail-closed [`AzureError::Command`] — never
//! a silent miss.
//!
//! FAIL-CLOSED — the deliberate opposite of the keychain provider's fail-open. A
//! reference you asked to resolve but couldn't (`az` absent, not authenticated,
//! bad reference, timeout, or empty output) is an ERROR, never a silent
//! pass-through: a secret you requested but didn't get is a bug, not a default.
//!
//! Injection-safe: the vault + name are passed as argv elements to `az keyvault
//! secret show`, never interpolated into a shell. The subprocess runs behind the
//! shared bounded [`Exec`] seam, so a hung CLI can't wedge resolution and tests
//! inject canned output without a real `az`.
//!
//! Docs: <https://learn.microsoft.com/en-us/cli/azure/keyvault/secret>

use std::time::Duration;

use indexmap::IndexMap;

use crate::providers::keychain::Exec;

/// The Azure Key Vault secret-reference scheme.
pub const AZURE_PREFIX: &str = "azure://";

/// Default per-`az keyvault secret show` deadline. Matches the other resolvers'
/// 10 s — a bounded window that tolerates a slow API round-trip without wedging
/// resolution. Tunable via `ConfigOptions.azure_timeout`.
pub const DEFAULT_AZURE_TIMEOUT: Duration = Duration::from_secs(10);

/// An `azure://` resolution failure. Every variant is surfaced (fail-closed),
/// never swallowed into a silent empty or a literal pass-through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AzureError {
  /// `az` could not be spawned — not installed, or not on `PATH`.
  Spawn { reference: String, message: String },
  /// `az keyvault secret show` exited non-zero — not authenticated, bad vault or
  /// name, or no access.
  Command {
    reference: String,
    code: Option<i32>,
  },
  /// `az keyvault secret show` exceeded its deadline.
  Timeout { reference: String },
  /// `az keyvault secret show` succeeded but printed nothing — no secret to
  /// inject.
  Empty { reference: String },
  /// The reference is not `azure://<vault>/<name>`.
  InvalidReference { reference: String },
}

impl AzureError {
  /// The `azure://` reference the failure is about.
  pub fn reference(&self) -> &str {
    match self {
      AzureError::Spawn { reference, .. }
      | AzureError::Command { reference, .. }
      | AzureError::Timeout { reference }
      | AzureError::Empty { reference }
      | AzureError::InvalidReference { reference } => reference,
    }
  }

  /// A human-readable message: what failed, for which reference, and how to
  /// diagnose it.
  pub fn message(&self) -> String {
    let reference = self.reference();
    let cause = match self {
      AzureError::Spawn { message, .. } => {
        format!("could not run the Azure CLI (`az`): {message} — is it installed and on PATH?")
      }
      AzureError::Command { code, .. } => match code {
        Some(code) => format!(
          "`az keyvault secret show` exited {code} — authenticate the CLI (`az login`) and check the vault and name"
        ),
        None => "`az keyvault secret show` was terminated by a signal".to_string(),
      },
      AzureError::Timeout { .. } => "`az keyvault secret show` exceeded its deadline".to_string(),
      AzureError::Empty { .. } => "`az keyvault secret show` returned no secret".to_string(),
      AzureError::InvalidReference { .. } => {
        "not an `azure://<vault>/<name>` reference".to_string()
      }
    };
    format!("azure:// resolution failed for `{reference}`: {cause}.")
  }
}

/// True when `value` is an Azure Key Vault secret reference (`azure://…`).
pub fn is_azure_reference(value: &str) -> bool {
  value.starts_with(AZURE_PREFIX)
}

/// Parse `azure://<vault>/<name>` into its `(vault, name)`. The reference splits
/// on `/` into exactly two segments, both non-empty.
pub fn parse_azure_reference(reference: &str) -> Result<(String, String), AzureError> {
  let rest = reference.strip_prefix(AZURE_PREFIX).unwrap_or(reference);
  let parts: Vec<&str> = rest.split('/').collect();
  if parts.len() != 2 {
    return Err(AzureError::InvalidReference {
      reference: reference.to_string(),
    });
  }
  let (vault, name) = (parts[0], parts[1]);
  if vault.is_empty() || name.is_empty() {
    return Err(AzureError::InvalidReference {
      reference: reference.to_string(),
    });
  }
  Ok((vault.to_string(), name.to_string()))
}

/// Read one `azure://` reference by running `az keyvault secret show --vault-name
/// <vault> --name <name> --query value -o tsv` through `exec`. Fail-closed: a bad
/// reference, spawn error, timeout, non-zero exit, or empty output is an
/// [`AzureError`]. On success the secret is returned with a single trailing
/// newline stripped, inner content untouched.
pub fn read_azure_reference(
  exec: &dyn Exec,
  reference: &str,
  timeout: Duration,
) -> Result<String, AzureError> {
  let (vault, name) = parse_azure_reference(reference)?;
  let output = match exec.exec_file(
    "az",
    &[
      "keyvault",
      "secret",
      "show",
      "--vault-name",
      &vault,
      "--name",
      &name,
      "--query",
      "value",
      "-o",
      "tsv",
    ],
    timeout,
  ) {
    Ok(output) => output,
    Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
      return Err(AzureError::Timeout {
        reference: reference.to_string(),
      });
    }
    Err(err) => {
      return Err(AzureError::Spawn {
        reference: reference.to_string(),
        message: err.to_string(),
      });
    }
  };
  if !output.status.success() {
    return Err(AzureError::Command {
      reference: reference.to_string(),
      code: output.status.code(),
    });
  }
  // `-o tsv` prints the value followed by one newline (`\n`, or `\r\n` on
  // Windows); strip exactly that trailing line ending and keep interior bytes.
  let raw = String::from_utf8_lossy(&output.stdout);
  let raw: &str = raw.as_ref();
  let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
  let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
  let secret = trimmed.to_string();
  if secret.is_empty() {
    return Err(AzureError::Empty {
      reference: reference.to_string(),
    });
  }
  Ok(secret)
}

/// Replace every `azure://` value in `map` IN PLACE with its resolved secret, via
/// `exec`. Values that are not references are left untouched. Fail-closed: the
/// FIRST reference that fails to resolve (insertion order) returns its
/// [`AzureError`]; references resolved before it are already substituted, and the
/// failing one keeps its literal `azure://` value so the failure is never
/// mistaken for a real secret.
pub fn resolve_azure_references(
  map: &mut IndexMap<String, String>,
  exec: &dyn Exec,
  timeout: Duration,
) -> Result<(), AzureError> {
  let references: Vec<(String, String)> = map
    .iter()
    .filter(|(_, value)| is_azure_reference(value))
    .map(|(key, value)| (key.clone(), value.clone()))
    .collect();
  for (key, reference) in references {
    let secret = read_azure_reference(exec, &reference, timeout)?;
    map.insert(key, secret);
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::process::Output;

  use super::*;
  use crate::providers::keychain::exit_status_from_code;

  /// Canned [`Exec`] recording the argv it saw and replaying a scripted result.
  struct FakeExec {
    result: std::io::Result<Output>,
  }

  impl FakeExec {
    fn ok(stdout: &str, code: i32) -> Self {
      FakeExec {
        result: Ok(Output {
          status: exit_status_from_code(code),
          stdout: stdout.as_bytes().to_vec(),
          stderr: Vec::new(),
        }),
      }
    }

    fn err(err: std::io::Error) -> Self {
      FakeExec { result: Err(err) }
    }
  }

  impl Exec for FakeExec {
    fn exec_file(&self, path: &str, args: &[&str], _timeout: Duration) -> std::io::Result<Output> {
      assert_eq!(path, "az");
      assert_eq!(
        args,
        [
          "keyvault",
          "secret",
          "show",
          "--vault-name",
          VAULT,
          "--name",
          NAME,
          "--query",
          "value",
          "-o",
          "tsv",
        ]
      );
      match &self.result {
        Ok(output) => Ok(output.clone()),
        Err(err) => Err(std::io::Error::new(err.kind(), err.to_string())),
      }
    }
  }

  const VAULT: &str = "my-vault";
  const NAME: &str = "db-password";
  const REF: &str = "azure://my-vault/db-password";

  #[test]
  fn is_azure_reference_matches_only_the_scheme() {
    assert!(is_azure_reference(REF));
    assert!(!is_azure_reference("plain"));
    assert!(!is_azure_reference("bw://x/password"));
    assert!(!is_azure_reference(""));
  }

  #[test]
  fn parse_accepts_a_vault_and_name() {
    assert_eq!(
      parse_azure_reference(REF).unwrap(),
      (VAULT.to_string(), NAME.to_string())
    );
  }

  #[test]
  fn parse_rejects_a_missing_name_segment() {
    // `azure://my-vault` — only one segment, no `/<name>`.
    assert!(matches!(
      parse_azure_reference("azure://my-vault"),
      Err(AzureError::InvalidReference { .. })
    ));
  }

  #[test]
  fn parse_rejects_an_extra_segment() {
    // `azure://my-vault/db-password/extra` — three segments.
    assert!(matches!(
      parse_azure_reference("azure://my-vault/db-password/extra"),
      Err(AzureError::InvalidReference { .. })
    ));
  }

  #[test]
  fn parse_rejects_an_empty_vault() {
    // `azure:///db-password` — a name but no vault before the `/`.
    assert!(matches!(
      parse_azure_reference("azure:///db-password"),
      Err(AzureError::InvalidReference { .. })
    ));
  }

  #[test]
  fn parse_rejects_an_empty_name() {
    // `azure://my-vault/` — a vault but no name after the `/`.
    assert!(matches!(
      parse_azure_reference("azure://my-vault/"),
      Err(AzureError::InvalidReference { .. })
    ));
  }

  #[test]
  fn read_strips_one_trailing_newline() {
    let exec = FakeExec::ok("s3cr3t\n", 0);
    assert_eq!(
      read_azure_reference(&exec, REF, DEFAULT_AZURE_TIMEOUT).unwrap(),
      "s3cr3t"
    );
  }

  #[test]
  fn read_fails_closed_on_unauthenticated_nonzero_exit() {
    let exec = FakeExec::ok("", 1);
    assert_eq!(
      read_azure_reference(&exec, REF, DEFAULT_AZURE_TIMEOUT),
      Err(AzureError::Command {
        reference: REF.to_string(),
        code: Some(1),
      })
    );
  }

  #[test]
  fn read_maps_spawn_failure_to_spawn_error() {
    let exec = FakeExec::err(std::io::Error::new(std::io::ErrorKind::NotFound, "no az"));
    assert!(matches!(
      read_azure_reference(&exec, REF, DEFAULT_AZURE_TIMEOUT),
      Err(AzureError::Spawn { .. })
    ));
  }

  #[test]
  fn read_maps_deadline_to_timeout_error() {
    let exec = FakeExec::err(std::io::Error::new(
      std::io::ErrorKind::TimedOut,
      "deadline",
    ));
    assert_eq!(
      read_azure_reference(&exec, REF, DEFAULT_AZURE_TIMEOUT),
      Err(AzureError::Timeout {
        reference: REF.to_string(),
      })
    );
  }

  #[test]
  fn read_fails_closed_on_empty_output() {
    let exec = FakeExec::ok("\n", 0);
    assert_eq!(
      read_azure_reference(&exec, REF, DEFAULT_AZURE_TIMEOUT),
      Err(AzureError::Empty {
        reference: REF.to_string(),
      })
    );
  }

  #[test]
  fn read_keeps_interior_content() {
    let exec = FakeExec::ok("line1\nline2\n", 0);
    assert_eq!(
      read_azure_reference(&exec, REF, DEFAULT_AZURE_TIMEOUT).unwrap(),
      "line1\nline2"
    );
  }

  #[test]
  fn resolve_replaces_only_azure_values() {
    let exec = FakeExec::ok("s3cr3t\n", 0);
    let mut map = IndexMap::new();
    map.insert("PLAIN".to_string(), "keep".to_string());
    map.insert("SECRET".to_string(), REF.to_string());
    resolve_azure_references(&mut map, &exec, DEFAULT_AZURE_TIMEOUT).unwrap();
    assert_eq!(map["PLAIN"], "keep");
    assert_eq!(map["SECRET"], "s3cr3t");
  }

  #[test]
  fn resolve_is_a_noop_without_references() {
    let exec = FakeExec::ok("unused\n", 0);
    let mut map = IndexMap::new();
    map.insert("A".to_string(), "1".to_string());
    resolve_azure_references(&mut map, &exec, DEFAULT_AZURE_TIMEOUT).unwrap();
    assert_eq!(map["A"], "1");
  }

  #[test]
  fn azure_error_message_names_reference() {
    let msg = AzureError::Empty {
      reference: REF.to_string(),
    }
    .message();
    assert!(msg.contains(REF));
    assert!(msg.contains("az keyvault secret show"));
  }

  #[test]
  fn azure_error_message_covers_every_variant() {
    let spawn = AzureError::Spawn {
      reference: REF.to_string(),
      message: "no az".to_string(),
    }
    .message();
    assert!(spawn.contains(REF));
    assert!(spawn.contains("Azure CLI"));

    let command_code = AzureError::Command {
      reference: REF.to_string(),
      code: Some(2),
    }
    .message();
    assert!(command_code.contains("exited 2"));

    let command_signal = AzureError::Command {
      reference: REF.to_string(),
      code: None,
    }
    .message();
    assert!(command_signal.contains("signal"));

    let timeout = AzureError::Timeout {
      reference: REF.to_string(),
    }
    .message();
    assert!(timeout.contains("deadline"));

    let empty = AzureError::Empty {
      reference: REF.to_string(),
    }
    .message();
    assert!(empty.contains("no secret"));

    let invalid = AzureError::InvalidReference {
      reference: REF.to_string(),
    }
    .message();
    assert!(invalid.contains("azure://<vault>/<name>"));
  }
}
