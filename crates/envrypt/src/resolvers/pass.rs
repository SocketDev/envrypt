//! `pass` (Unix password store) `pass://` secret-reference resolution (opt-in,
//! fail-closed).
//!
//! A resolved env value of the form `pass://<path>` is replaced with the secret
//! the `pass` CLI prints for it (`pass show <path>`). The `<path>` is the entry's
//! store path, mirroring the familiar `API_KEY="pass://email/work"` shape, the
//! companion to [`super::bitwarden`].
//!
//! Runs ONLY when the caller opts in (an `Exec` is threaded through
//! [`crate::resolvers::envs::ConfigOptions::pass_exec`]); a stored `pass://`
//! string is inert by default, so nothing shells out unless the consumer asked
//! for it.
//!
//! SESSION — `pass show` decrypts through a `gpg-agent` reachable from the process
//! environment, which the spawned child inherits from this process. A store the
//! agent cannot decrypt (locked key, missing entry) makes `pass show` exit
//! non-zero, which surfaces as a fail-closed [`PassError::Command`] — never a
//! silent miss.
//!
//! FAIL-CLOSED — the deliberate opposite of the keychain provider's fail-open. A
//! reference you asked to resolve but couldn't (`pass` absent, locked key, bad
//! reference, timeout, or empty output) is an ERROR, never a silent pass-through:
//! a secret you requested but didn't get is a bug, not a default.
//!
//! Injection-safe: the path is passed as an argv element to `pass show`, never
//! interpolated into a shell. The subprocess runs behind the shared bounded
//! [`Exec`] seam, so a hung passphrase prompt can't wedge resolution and tests
//! inject canned output without a real `pass`.
//!
//! Docs: <https://www.passwordstore.org/>

use std::time::Duration;

use indexmap::IndexMap;

use crate::providers::keychain::Exec;

/// The `pass` (Unix password store) secret-reference scheme.
pub const PASS_PREFIX: &str = "pass://";

/// Default per-`pass show` deadline. Matches the other resolvers' 10 s — a
/// bounded window that tolerates a slow gpg-agent decrypt without wedging
/// resolution. Tunable via `ConfigOptions.pass_timeout`.
pub const DEFAULT_PASS_TIMEOUT: Duration = Duration::from_secs(10);

/// A `pass://` resolution failure. Every variant is surfaced (fail-closed), never
/// swallowed into a silent empty or a literal pass-through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassError {
    /// `pass` could not be spawned — not installed, or not on `PATH`.
    Spawn { reference: String, message: String },
    /// `pass show` exited non-zero — locked key, missing entry, or no access.
    Command {
        reference: String,
        code: Option<i32>,
    },
    /// `pass show` exceeded its deadline.
    Timeout { reference: String },
    /// `pass show` succeeded but printed nothing — no secret to inject.
    Empty { reference: String },
    /// The reference is not `pass://<path>`.
    InvalidReference { reference: String },
}

impl PassError {
    /// The `pass://` reference the failure is about.
    pub fn reference(&self) -> &str {
        match self {
            PassError::Spawn { reference, .. }
            | PassError::Command { reference, .. }
            | PassError::Timeout { reference }
            | PassError::Empty { reference }
            | PassError::InvalidReference { reference } => reference,
        }
    }

    /// A human-readable message: what failed, for which reference, and how to
    /// diagnose it.
    pub fn message(&self) -> String {
        let reference = self.reference();
        let cause = match self {
      PassError::Spawn { message, .. } => {
        format!("could not run the pass CLI (`pass`): {message} — is it installed and on PATH?")
      }
      PassError::Command { code, .. } => match code {
        Some(code) => format!(
          "`pass show` exited {code} — unlock the CLI (a gpg-agent able to decrypt the store) and check the path"
        ),
        None => "`pass show` was terminated by a signal".to_string(),
      },
      PassError::Timeout { .. } => "`pass show` exceeded its deadline".to_string(),
      PassError::Empty { .. } => "`pass show` returned no secret".to_string(),
      PassError::InvalidReference { .. } => "not a `pass://<path>` reference".to_string(),
    };
        format!("pass:// resolution failed for `{reference}`: {cause}.")
    }
}

/// True when `value` is a `pass` secret reference (`pass://…`).
pub fn is_pass_reference(value: &str) -> bool {
    value.starts_with(PASS_PREFIX)
}

/// Parse `pass://<path>` into its `path`. The remainder after the scheme is the
/// entry's store path and must be non-empty.
pub fn parse_pass_reference(reference: &str) -> Result<String, PassError> {
    let path = reference.strip_prefix(PASS_PREFIX).unwrap_or(reference);
    if path.is_empty() {
        return Err(PassError::InvalidReference {
            reference: reference.to_string(),
        });
    }
    Ok(path.to_string())
}

/// Read one `pass://` reference by running `pass show <path>` through `exec`.
/// Fail-closed: a bad reference, spawn error, timeout, non-zero exit, or empty
/// output is a [`PassError`]. On success the secret is returned with a single
/// trailing newline stripped, inner content untouched.
pub fn read_pass_reference(
    exec: &dyn Exec,
    reference: &str,
    timeout: Duration,
) -> Result<String, PassError> {
    let path = parse_pass_reference(reference)?;
    let output = match exec.exec_file("pass", &["show", &path], timeout) {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
            return Err(PassError::Timeout {
                reference: reference.to_string(),
            });
        }
        Err(err) => {
            return Err(PassError::Spawn {
                reference: reference.to_string(),
                message: err.to_string(),
            });
        }
    };
    if !output.status.success() {
        return Err(PassError::Command {
            reference: reference.to_string(),
            code: output.status.code(),
        });
    }
    // `pass show` prints the first line (the secret) followed by one newline (`\n`,
    // or `\r\n` on Windows); strip exactly that trailing line ending and keep
    // interior bytes.
    let raw = String::from_utf8_lossy(&output.stdout);
    let raw: &str = raw.as_ref();
    let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    let secret = trimmed.to_string();
    if secret.is_empty() {
        return Err(PassError::Empty {
            reference: reference.to_string(),
        });
    }
    Ok(secret)
}

/// Replace every `pass://` value in `map` IN PLACE with its resolved secret, via
/// `exec`. Values that are not references are left untouched. Fail-closed: the
/// FIRST reference that fails to resolve (insertion order) returns its
/// [`PassError`]; references resolved before it are already substituted, and the
/// failing one keeps its literal `pass://` value so the failure is never mistaken
/// for a real secret.
pub fn resolve_pass_references(
    map: &mut IndexMap<String, String>,
    exec: &dyn Exec,
    timeout: Duration,
) -> Result<(), PassError> {
    let references: Vec<(String, String)> = map
        .iter()
        .filter(|(_, value)| is_pass_reference(value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    for (key, reference) in references {
        let secret = read_pass_reference(exec, &reference, timeout)?;
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
            assert_eq!(path, "pass");
            assert_eq!(args, ["show", PATH]);
            match &self.result {
                Ok(output) => Ok(output.clone()),
                Err(err) => Err(std::io::Error::new(err.kind(), err.to_string())),
            }
        }
    }

    const PATH: &str = "email/work";
    const REF: &str = "pass://email/work";

    #[test]
    fn is_pass_reference_matches_only_the_scheme() {
        assert!(is_pass_reference(REF));
        assert!(!is_pass_reference("plain"));
        assert!(!is_pass_reference("bw://x/password"));
        assert!(!is_pass_reference(""));
    }

    #[test]
    fn parse_accepts_a_path() {
        assert_eq!(parse_pass_reference(REF).unwrap(), PATH.to_string());
    }

    #[test]
    fn parse_rejects_an_empty_path() {
        // `pass://` — the scheme with no path after it.
        assert!(matches!(
            parse_pass_reference("pass://"),
            Err(PassError::InvalidReference { .. })
        ));
    }

    #[test]
    fn read_strips_one_trailing_newline() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        assert_eq!(
            read_pass_reference(&exec, REF, DEFAULT_PASS_TIMEOUT).unwrap(),
            "s3cr3t"
        );
    }

    #[test]
    fn read_fails_closed_on_locked_key_nonzero_exit() {
        let exec = FakeExec::ok("", 1);
        assert_eq!(
            read_pass_reference(&exec, REF, DEFAULT_PASS_TIMEOUT),
            Err(PassError::Command {
                reference: REF.to_string(),
                code: Some(1),
            })
        );
    }

    #[test]
    fn read_maps_spawn_failure_to_spawn_error() {
        let exec = FakeExec::err(std::io::Error::new(std::io::ErrorKind::NotFound, "no pass"));
        assert!(matches!(
            read_pass_reference(&exec, REF, DEFAULT_PASS_TIMEOUT),
            Err(PassError::Spawn { .. })
        ));
    }

    #[test]
    fn read_maps_deadline_to_timeout_error() {
        let exec = FakeExec::err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "deadline",
        ));
        assert_eq!(
            read_pass_reference(&exec, REF, DEFAULT_PASS_TIMEOUT),
            Err(PassError::Timeout {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn read_fails_closed_on_empty_output() {
        let exec = FakeExec::ok("\n", 0);
        assert_eq!(
            read_pass_reference(&exec, REF, DEFAULT_PASS_TIMEOUT),
            Err(PassError::Empty {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn read_keeps_interior_content() {
        let exec = FakeExec::ok("line1\nline2\n", 0);
        assert_eq!(
            read_pass_reference(&exec, REF, DEFAULT_PASS_TIMEOUT).unwrap(),
            "line1\nline2"
        );
    }

    #[test]
    fn resolve_replaces_only_pass_values() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        let mut map = IndexMap::new();
        map.insert("PLAIN".to_string(), "keep".to_string());
        map.insert("SECRET".to_string(), REF.to_string());
        resolve_pass_references(&mut map, &exec, DEFAULT_PASS_TIMEOUT).unwrap();
        assert_eq!(map["PLAIN"], "keep");
        assert_eq!(map["SECRET"], "s3cr3t");
    }

    #[test]
    fn resolve_is_a_noop_without_references() {
        let exec = FakeExec::ok("unused\n", 0);
        let mut map = IndexMap::new();
        map.insert("A".to_string(), "1".to_string());
        resolve_pass_references(&mut map, &exec, DEFAULT_PASS_TIMEOUT).unwrap();
        assert_eq!(map["A"], "1");
    }

    #[test]
    fn pass_error_message_names_reference() {
        let msg = PassError::Empty {
            reference: REF.to_string(),
        }
        .message();
        assert!(msg.contains(REF));
        assert!(msg.contains("pass show"));
    }

    #[test]
    fn pass_error_message_covers_every_variant() {
        let spawn = PassError::Spawn {
            reference: REF.to_string(),
            message: "no pass".to_string(),
        }
        .message();
        assert!(spawn.contains(REF));
        assert!(spawn.contains("pass CLI"));

        let command_code = PassError::Command {
            reference: REF.to_string(),
            code: Some(2),
        }
        .message();
        assert!(command_code.contains("exited 2"));

        let command_signal = PassError::Command {
            reference: REF.to_string(),
            code: None,
        }
        .message();
        assert!(command_signal.contains("signal"));

        let timeout = PassError::Timeout {
            reference: REF.to_string(),
        }
        .message();
        assert!(timeout.contains("deadline"));

        let empty = PassError::Empty {
            reference: REF.to_string(),
        }
        .message();
        assert!(empty.contains("no secret"));

        let invalid = PassError::InvalidReference {
            reference: REF.to_string(),
        }
        .message();
        assert!(invalid.contains("pass://<path>"));
    }
}
