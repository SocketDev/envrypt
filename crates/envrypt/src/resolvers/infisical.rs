//! Infisical `infisical://` secret-reference resolution (opt-in, fail-closed).
//!
//! A resolved env value of the form `infisical://<name>` is replaced with the
//! secret the Infisical CLI prints for it (`infisical secrets get <name> --plain
//! --silent`). The `<name>` is the secret's name, mirroring the familiar
//! `API_KEY="infisical://DATABASE_URL"` shape, the companion to
//! [`super::bitwarden`].
//!
//! Runs ONLY when the caller opts in (an `Exec` is threaded through
//! [`crate::resolvers::envs::ConfigOptions::infisical_exec`]); a stored
//! `infisical://` string is inert by default, so nothing shells out unless the
//! consumer asked for it.
//!
//! SESSION — `infisical` reads its session from `infisical login` (or an
//! `INFISICAL_TOKEN`) in the process environment, which the spawned child
//! inherits from this process. An unauthenticated CLI exits non-zero, which
//! surfaces as a fail-closed [`InfisicalError::Command`] — never a silent miss.
//!
//! FAIL-CLOSED — the deliberate opposite of the keychain provider's fail-open. A
//! reference you asked to resolve but couldn't (`infisical` absent, not
//! authenticated, bad reference, timeout, or empty output) is an ERROR, never a
//! silent pass-through: a secret you requested but didn't get is a bug, not a
//! default.
//!
//! Injection-safe: the name is passed as an argv element to `infisical secrets
//! get`, never interpolated into a shell. The subprocess runs behind the shared
//! bounded [`Exec`] seam, so a hung CLI can't wedge resolution and tests inject
//! canned output without a real `infisical`.
//!
//! Docs: <https://infisical.com/docs/cli/commands/secrets>

use std::time::Duration;

use indexmap::IndexMap;

use crate::providers::keychain::Exec;

/// The Infisical secret-reference scheme.
pub const INFISICAL_PREFIX: &str = "infisical://";

/// Default per-`infisical secrets get` deadline. Matches the other resolvers'
/// 10 s — a bounded window that tolerates a slow API round-trip without wedging
/// resolution. Tunable via `ConfigOptions.infisical_timeout`.
pub const DEFAULT_INFISICAL_TIMEOUT: Duration = Duration::from_secs(10);

/// An `infisical://` resolution failure. Every variant is surfaced (fail-closed),
/// never swallowed into a silent empty or a literal pass-through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfisicalError {
    /// `infisical` could not be spawned — not installed, or not on `PATH`.
    Spawn { reference: String, message: String },
    /// `infisical secrets get` exited non-zero — not authenticated, bad name, or no
    /// access.
    Command {
        reference: String,
        code: Option<i32>,
    },
    /// `infisical secrets get` exceeded its deadline.
    Timeout { reference: String },
    /// `infisical secrets get` succeeded but printed nothing — no secret to inject.
    Empty { reference: String },
    /// The reference is not `infisical://<name>`.
    InvalidReference { reference: String },
}

impl InfisicalError {
    /// The `infisical://` reference the failure is about.
    pub fn reference(&self) -> &str {
        match self {
            InfisicalError::Spawn { reference, .. }
            | InfisicalError::Command { reference, .. }
            | InfisicalError::Timeout { reference }
            | InfisicalError::Empty { reference }
            | InfisicalError::InvalidReference { reference } => reference,
        }
    }

    /// A human-readable message: what failed, for which reference, and how to
    /// diagnose it.
    pub fn message(&self) -> String {
        let reference = self.reference();
        let cause = match self {
      InfisicalError::Spawn { message, .. } => {
        format!("could not run the Infisical CLI (`infisical`): {message} — is it installed and on PATH?")
      }
      InfisicalError::Command { code, .. } => match code {
        Some(code) => format!(
          "`infisical secrets get` exited {code} — authenticate the CLI (`infisical login` or `INFISICAL_TOKEN`) and check the name"
        ),
        None => "`infisical secrets get` was terminated by a signal".to_string(),
      },
      InfisicalError::Timeout { .. } => "`infisical secrets get` exceeded its deadline".to_string(),
      InfisicalError::Empty { .. } => "`infisical secrets get` returned no secret".to_string(),
      InfisicalError::InvalidReference { .. } => "not an `infisical://<name>` reference".to_string(),
    };
        format!("infisical:// resolution failed for `{reference}`: {cause}.")
    }
}

/// True when `value` is an Infisical secret reference (`infisical://…`).
pub fn is_infisical_reference(value: &str) -> bool {
    value.starts_with(INFISICAL_PREFIX)
}

/// Parse `infisical://<name>` into its `name`. The remainder after the scheme is
/// the secret's name and must be non-empty.
pub fn parse_infisical_reference(reference: &str) -> Result<String, InfisicalError> {
    let name = reference
        .strip_prefix(INFISICAL_PREFIX)
        .unwrap_or(reference);
    if name.is_empty() {
        return Err(InfisicalError::InvalidReference {
            reference: reference.to_string(),
        });
    }
    Ok(name.to_string())
}

/// Read one `infisical://` reference by running `infisical secrets get <name>
/// --plain --silent` through `exec`. Fail-closed: a bad reference, spawn error,
/// timeout, non-zero exit, or empty output is an [`InfisicalError`]. On success
/// the secret is returned with a single trailing newline stripped, inner content
/// untouched.
pub fn read_infisical_reference(
    exec: &dyn Exec,
    reference: &str,
    timeout: Duration,
) -> Result<String, InfisicalError> {
    let name = parse_infisical_reference(reference)?;
    let output = match exec.exec_file(
        "infisical",
        &["secrets", "get", &name, "--plain", "--silent"],
        timeout,
    ) {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
            return Err(InfisicalError::Timeout {
                reference: reference.to_string(),
            });
        }
        Err(err) => {
            return Err(InfisicalError::Spawn {
                reference: reference.to_string(),
                message: err.to_string(),
            });
        }
    };
    if !output.status.success() {
        return Err(InfisicalError::Command {
            reference: reference.to_string(),
            code: output.status.code(),
        });
    }
    // `infisical secrets get --plain` prints the value followed by one newline
    // (`\n`, or `\r\n` on Windows); strip exactly that trailing line ending and
    // keep interior bytes.
    let raw = String::from_utf8_lossy(&output.stdout);
    let raw: &str = raw.as_ref();
    let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    let secret = trimmed.to_string();
    if secret.is_empty() {
        return Err(InfisicalError::Empty {
            reference: reference.to_string(),
        });
    }
    Ok(secret)
}

/// Replace every `infisical://` value in `map` IN PLACE with its resolved secret,
/// via `exec`. Values that are not references are left untouched. Fail-closed:
/// the FIRST reference that fails to resolve (insertion order) returns its
/// [`InfisicalError`]; references resolved before it are already substituted, and
/// the failing one keeps its literal `infisical://` value so the failure is never
/// mistaken for a real secret.
pub fn resolve_infisical_references(
    map: &mut IndexMap<String, String>,
    exec: &dyn Exec,
    timeout: Duration,
) -> Result<(), InfisicalError> {
    let references: Vec<(String, String)> = map
        .iter()
        .filter(|(_, value)| is_infisical_reference(value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    for (key, reference) in references {
        let secret = read_infisical_reference(exec, &reference, timeout)?;
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
            assert_eq!(path, "infisical");
            assert_eq!(args, ["secrets", "get", NAME, "--plain", "--silent"]);
            match &self.result {
                Ok(output) => Ok(output.clone()),
                Err(err) => Err(std::io::Error::new(err.kind(), err.to_string())),
            }
        }
    }

    const NAME: &str = "DATABASE_URL";
    const REF: &str = "infisical://DATABASE_URL";

    #[test]
    fn is_infisical_reference_matches_only_the_scheme() {
        assert!(is_infisical_reference(REF));
        assert!(!is_infisical_reference("plain"));
        assert!(!is_infisical_reference("bw://x/password"));
        assert!(!is_infisical_reference(""));
    }

    #[test]
    fn parse_accepts_a_name() {
        assert_eq!(parse_infisical_reference(REF).unwrap(), NAME.to_string());
    }

    #[test]
    fn parse_rejects_an_empty_name() {
        // `infisical://` — the scheme with no name after it.
        assert!(matches!(
            parse_infisical_reference("infisical://"),
            Err(InfisicalError::InvalidReference { .. })
        ));
    }

    #[test]
    fn read_strips_one_trailing_newline() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        assert_eq!(
            read_infisical_reference(&exec, REF, DEFAULT_INFISICAL_TIMEOUT).unwrap(),
            "s3cr3t"
        );
    }

    #[test]
    fn read_fails_closed_on_unauthenticated_nonzero_exit() {
        let exec = FakeExec::ok("", 1);
        assert_eq!(
            read_infisical_reference(&exec, REF, DEFAULT_INFISICAL_TIMEOUT),
            Err(InfisicalError::Command {
                reference: REF.to_string(),
                code: Some(1),
            })
        );
    }

    #[test]
    fn read_maps_spawn_failure_to_spawn_error() {
        let exec = FakeExec::err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no infisical",
        ));
        assert!(matches!(
            read_infisical_reference(&exec, REF, DEFAULT_INFISICAL_TIMEOUT),
            Err(InfisicalError::Spawn { .. })
        ));
    }

    #[test]
    fn read_maps_deadline_to_timeout_error() {
        let exec = FakeExec::err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "deadline",
        ));
        assert_eq!(
            read_infisical_reference(&exec, REF, DEFAULT_INFISICAL_TIMEOUT),
            Err(InfisicalError::Timeout {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn read_fails_closed_on_empty_output() {
        let exec = FakeExec::ok("\n", 0);
        assert_eq!(
            read_infisical_reference(&exec, REF, DEFAULT_INFISICAL_TIMEOUT),
            Err(InfisicalError::Empty {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn read_keeps_interior_content() {
        let exec = FakeExec::ok("line1\nline2\n", 0);
        assert_eq!(
            read_infisical_reference(&exec, REF, DEFAULT_INFISICAL_TIMEOUT).unwrap(),
            "line1\nline2"
        );
    }

    #[test]
    fn resolve_replaces_only_infisical_values() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        let mut map = IndexMap::new();
        map.insert("PLAIN".to_string(), "keep".to_string());
        map.insert("SECRET".to_string(), REF.to_string());
        resolve_infisical_references(&mut map, &exec, DEFAULT_INFISICAL_TIMEOUT).unwrap();
        assert_eq!(map["PLAIN"], "keep");
        assert_eq!(map["SECRET"], "s3cr3t");
    }

    #[test]
    fn resolve_is_a_noop_without_references() {
        let exec = FakeExec::ok("unused\n", 0);
        let mut map = IndexMap::new();
        map.insert("A".to_string(), "1".to_string());
        resolve_infisical_references(&mut map, &exec, DEFAULT_INFISICAL_TIMEOUT).unwrap();
        assert_eq!(map["A"], "1");
    }

    #[test]
    fn infisical_error_message_names_reference() {
        let msg = InfisicalError::Empty {
            reference: REF.to_string(),
        }
        .message();
        assert!(msg.contains(REF));
        assert!(msg.contains("infisical secrets get"));
    }

    #[test]
    fn infisical_error_message_covers_every_variant() {
        let spawn = InfisicalError::Spawn {
            reference: REF.to_string(),
            message: "no infisical".to_string(),
        }
        .message();
        assert!(spawn.contains(REF));
        assert!(spawn.contains("Infisical CLI"));

        let command_code = InfisicalError::Command {
            reference: REF.to_string(),
            code: Some(2),
        }
        .message();
        assert!(command_code.contains("exited 2"));

        let command_signal = InfisicalError::Command {
            reference: REF.to_string(),
            code: None,
        }
        .message();
        assert!(command_signal.contains("signal"));

        let timeout = InfisicalError::Timeout {
            reference: REF.to_string(),
        }
        .message();
        assert!(timeout.contains("deadline"));

        let empty = InfisicalError::Empty {
            reference: REF.to_string(),
        }
        .message();
        assert!(empty.contains("no secret"));

        let invalid = InfisicalError::InvalidReference {
            reference: REF.to_string(),
        }
        .message();
        assert!(invalid.contains("infisical://<name>"));
    }
}
