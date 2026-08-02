//! HashiCorp Vault `vault://` secret-reference resolution (opt-in, fail-closed).
//!
//! A resolved env value of the form `vault://<path>#<field>` is replaced with the
//! secret the Vault CLI prints for it (`vault kv get -field=<field> <path>`). The
//! `<path>` is a KV mount path and `<field>` is the key to read, mirroring the
//! familiar `API_KEY="vault://secret/data/app#password"` shape, the companion to
//! [`super::bitwarden`].
//!
//! Runs ONLY when the caller opts in (an `Exec` is threaded through
//! [`crate::resolvers::envs::ConfigOptions::vault_exec`]); a stored `vault://`
//! string is inert by default, so nothing shells out unless the consumer asked
//! for it.
//!
//! SESSION — `vault kv get` reads its address and token from the process
//! environment (`VAULT_ADDR` + `VAULT_TOKEN`, or a logged-in `~/.vault-token`),
//! which the spawned child inherits from this process. An unauthenticated CLI
//! exits non-zero, which surfaces as a fail-closed [`VaultError::Command`] — never
//! a silent miss.
//!
//! FAIL-CLOSED — the deliberate opposite of the keychain provider's fail-open. A
//! reference you asked to resolve but couldn't (`vault` absent, not
//! authenticated, bad reference, timeout, or empty output) is an ERROR, never a
//! silent pass-through: a secret you requested but didn't get is a bug, not a
//! default.
//!
//! Injection-safe: the path + field are passed as argv elements to `vault kv
//! get`, never interpolated into a shell. The subprocess runs behind the shared
//! bounded [`Exec`] seam, so a hung CLI can't wedge resolution and tests inject
//! canned output without a real `vault`.
//!
//! Docs: <https://developer.hashicorp.com/vault/docs/commands/kv>

use std::time::Duration;

use indexmap::IndexMap;

use crate::providers::keychain::Exec;

/// The HashiCorp Vault secret-reference scheme.
pub const VAULT_PREFIX: &str = "vault://";

/// Default per-`vault kv get` deadline. Matches the other resolvers' 10 s — a
/// bounded window that tolerates a slow Vault round-trip without wedging
/// resolution. Tunable via `ConfigOptions.vault_timeout`.
pub const DEFAULT_VAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// A `vault://` resolution failure. Every variant is surfaced (fail-closed),
/// never swallowed into a silent empty or a literal pass-through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// `vault` could not be spawned — not installed, or not on `PATH`.
    Spawn { reference: String, message: String },
    /// `vault kv get` exited non-zero — not authenticated, bad path, or no access.
    Command {
        reference: String,
        code: Option<i32>,
    },
    /// `vault kv get` exceeded its deadline.
    Timeout { reference: String },
    /// `vault kv get` succeeded but printed nothing — no secret to inject.
    Empty { reference: String },
    /// The reference is not `vault://<path>#<field>`.
    InvalidReference { reference: String },
}

impl VaultError {
    /// The `vault://` reference the failure is about.
    pub fn reference(&self) -> &str {
        match self {
            VaultError::Spawn { reference, .. }
            | VaultError::Command { reference, .. }
            | VaultError::Timeout { reference }
            | VaultError::Empty { reference }
            | VaultError::InvalidReference { reference } => reference,
        }
    }

    /// A human-readable message: what failed, for which reference, and how to
    /// diagnose it.
    pub fn message(&self) -> String {
        let reference = self.reference();
        let cause = match self {
      VaultError::Spawn { message, .. } => {
        format!("could not run the Vault CLI (`vault`): {message} — is it installed and on PATH?")
      }
      VaultError::Command { code, .. } => match code {
        Some(code) => format!(
          "`vault kv get` exited {code} — authenticate the CLI (`VAULT_ADDR`/`VAULT_TOKEN`) and check the path"
        ),
        None => "`vault kv get` was terminated by a signal".to_string(),
      },
      VaultError::Timeout { .. } => "`vault kv get` exceeded its deadline".to_string(),
      VaultError::Empty { .. } => "`vault kv get` returned no secret".to_string(),
      VaultError::InvalidReference { .. } => {
        "not a `vault://<path>#<field>` reference".to_string()
      }
    };
        format!("vault:// resolution failed for `{reference}`: {cause}.")
    }
}

/// True when `value` is a HashiCorp Vault secret reference (`vault://…`).
pub fn is_vault_reference(value: &str) -> bool {
    value.starts_with(VAULT_PREFIX)
}

/// Parse `vault://<path>#<field>` into its `(path, field)`. The reference splits
/// on the FIRST `#`; both the path and the field must be non-empty.
pub fn parse_vault_reference(reference: &str) -> Result<(String, String), VaultError> {
    let rest = reference.strip_prefix(VAULT_PREFIX).unwrap_or(reference);
    let (path, field) = match rest.split_once('#') {
        Some((path, field)) => (path, field),
        None => {
            return Err(VaultError::InvalidReference {
                reference: reference.to_string(),
            })
        }
    };
    if path.is_empty() || field.is_empty() {
        return Err(VaultError::InvalidReference {
            reference: reference.to_string(),
        });
    }
    Ok((path.to_string(), field.to_string()))
}

/// Read one `vault://` reference by running `vault kv get -field=<field> <path>`
/// through `exec`. Fail-closed: a bad reference, spawn error, timeout, non-zero
/// exit, or empty output is a [`VaultError`]. On success the secret is returned
/// with a single trailing newline stripped, inner content untouched.
pub fn read_vault_reference(
    exec: &dyn Exec,
    reference: &str,
    timeout: Duration,
) -> Result<String, VaultError> {
    let (path, field) = parse_vault_reference(reference)?;
    let field_arg = format!("-field={field}");
    let output = match exec.exec_file("vault", &["kv", "get", &field_arg, &path], timeout) {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
            return Err(VaultError::Timeout {
                reference: reference.to_string(),
            });
        }
        Err(err) => {
            return Err(VaultError::Spawn {
                reference: reference.to_string(),
                message: err.to_string(),
            });
        }
    };
    if !output.status.success() {
        return Err(VaultError::Command {
            reference: reference.to_string(),
            code: output.status.code(),
        });
    }
    // `vault kv get -field=…` prints the value followed by one newline (`\n`, or
    // `\r\n` on Windows); strip exactly that trailing line ending and keep interior
    // bytes.
    let raw = String::from_utf8_lossy(&output.stdout);
    let raw: &str = raw.as_ref();
    let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    let secret = trimmed.to_string();
    if secret.is_empty() {
        return Err(VaultError::Empty {
            reference: reference.to_string(),
        });
    }
    Ok(secret)
}

/// Replace every `vault://` value in `map` IN PLACE with its resolved secret, via
/// `exec`. Values that are not references are left untouched. Fail-closed: the
/// FIRST reference that fails to resolve (insertion order) returns its
/// [`VaultError`]; references resolved before it are already substituted, and the
/// failing one keeps its literal `vault://` value so the failure is never
/// mistaken for a real secret.
pub fn resolve_vault_references(
    map: &mut IndexMap<String, String>,
    exec: &dyn Exec,
    timeout: Duration,
) -> Result<(), VaultError> {
    let references: Vec<(String, String)> = map
        .iter()
        .filter(|(_, value)| is_vault_reference(value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    for (key, reference) in references {
        let secret = read_vault_reference(exec, &reference, timeout)?;
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
        fn exec_file(
            &self,
            path: &str,
            args: &[&str],
            _timeout: Duration,
        ) -> std::io::Result<Output> {
            assert_eq!(path, "vault");
            assert_eq!(args, ["kv", "get", "-field=password", PATH]);
            match &self.result {
                Ok(output) => Ok(output.clone()),
                Err(err) => Err(std::io::Error::new(err.kind(), err.to_string())),
            }
        }
    }

    const PATH: &str = "secret/data/app";
    const REF: &str = "vault://secret/data/app#password";

    #[test]
    fn is_vault_reference_matches_only_the_scheme() {
        assert!(is_vault_reference(REF));
        assert!(!is_vault_reference("plain"));
        assert!(!is_vault_reference("bw://x/password"));
        assert!(!is_vault_reference(""));
    }

    #[test]
    fn parse_accepts_a_path_and_field() {
        assert_eq!(
            parse_vault_reference(REF).unwrap(),
            (PATH.to_string(), "password".to_string())
        );
    }

    #[test]
    fn parse_rejects_a_reference_without_a_field_separator() {
        assert!(matches!(
            parse_vault_reference("vault://secret/data/app"),
            Err(VaultError::InvalidReference { .. })
        ));
    }

    #[test]
    fn parse_rejects_an_empty_path() {
        // `vault://#password` — a field but no path before the `#`.
        assert!(matches!(
            parse_vault_reference("vault://#password"),
            Err(VaultError::InvalidReference { .. })
        ));
    }

    #[test]
    fn parse_rejects_an_empty_field() {
        // `vault://secret/data/app#` — a valid path but no field after the `#`.
        assert!(matches!(
            parse_vault_reference("vault://secret/data/app#"),
            Err(VaultError::InvalidReference { .. })
        ));
    }

    #[test]
    fn parse_splits_on_the_first_hash() {
        // A `#` inside the field is kept verbatim (split on the FIRST `#`).
        assert_eq!(
            parse_vault_reference("vault://secret/data/app#a#b").unwrap(),
            ("secret/data/app".to_string(), "a#b".to_string())
        );
    }

    #[test]
    fn read_strips_one_trailing_newline() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        assert_eq!(
            read_vault_reference(&exec, REF, DEFAULT_VAULT_TIMEOUT).unwrap(),
            "s3cr3t"
        );
    }

    #[test]
    fn read_fails_closed_on_unauthenticated_nonzero_exit() {
        let exec = FakeExec::ok("", 2);
        assert_eq!(
            read_vault_reference(&exec, REF, DEFAULT_VAULT_TIMEOUT),
            Err(VaultError::Command {
                reference: REF.to_string(),
                code: Some(2),
            })
        );
    }

    #[test]
    fn read_maps_spawn_failure_to_spawn_error() {
        let exec = FakeExec::err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no vault",
        ));
        assert!(matches!(
            read_vault_reference(&exec, REF, DEFAULT_VAULT_TIMEOUT),
            Err(VaultError::Spawn { .. })
        ));
    }

    #[test]
    fn read_maps_deadline_to_timeout_error() {
        let exec = FakeExec::err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "deadline",
        ));
        assert_eq!(
            read_vault_reference(&exec, REF, DEFAULT_VAULT_TIMEOUT),
            Err(VaultError::Timeout {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn read_fails_closed_on_empty_output() {
        let exec = FakeExec::ok("\n", 0);
        assert_eq!(
            read_vault_reference(&exec, REF, DEFAULT_VAULT_TIMEOUT),
            Err(VaultError::Empty {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn read_keeps_interior_content() {
        let exec = FakeExec::ok("line1\nline2\n", 0);
        assert_eq!(
            read_vault_reference(&exec, REF, DEFAULT_VAULT_TIMEOUT).unwrap(),
            "line1\nline2"
        );
    }

    #[test]
    fn resolve_replaces_only_vault_values() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        let mut map = IndexMap::new();
        map.insert("PLAIN".to_string(), "keep".to_string());
        map.insert("SECRET".to_string(), REF.to_string());
        resolve_vault_references(&mut map, &exec, DEFAULT_VAULT_TIMEOUT).unwrap();
        assert_eq!(map["PLAIN"], "keep");
        assert_eq!(map["SECRET"], "s3cr3t");
    }

    #[test]
    fn resolve_is_a_noop_without_references() {
        let exec = FakeExec::ok("unused\n", 0);
        let mut map = IndexMap::new();
        map.insert("A".to_string(), "1".to_string());
        resolve_vault_references(&mut map, &exec, DEFAULT_VAULT_TIMEOUT).unwrap();
        assert_eq!(map["A"], "1");
    }

    #[test]
    fn vault_error_message_names_reference() {
        let msg = VaultError::Empty {
            reference: REF.to_string(),
        }
        .message();
        assert!(msg.contains(REF));
        assert!(msg.contains("vault kv get"));
    }

    #[test]
    fn vault_error_message_covers_every_variant() {
        let spawn = VaultError::Spawn {
            reference: REF.to_string(),
            message: "no vault".to_string(),
        }
        .message();
        assert!(spawn.contains(REF));
        assert!(spawn.contains("Vault CLI"));

        let command_code = VaultError::Command {
            reference: REF.to_string(),
            code: Some(2),
        }
        .message();
        assert!(command_code.contains("exited 2"));

        let command_signal = VaultError::Command {
            reference: REF.to_string(),
            code: None,
        }
        .message();
        assert!(command_signal.contains("signal"));

        let timeout = VaultError::Timeout {
            reference: REF.to_string(),
        }
        .message();
        assert!(timeout.contains("deadline"));

        let empty = VaultError::Empty {
            reference: REF.to_string(),
        }
        .message();
        assert!(empty.contains("no secret"));

        let invalid = VaultError::InvalidReference {
            reference: REF.to_string(),
        }
        .message();
        assert!(invalid.contains("vault://<path>#<field>"));
    }
}
