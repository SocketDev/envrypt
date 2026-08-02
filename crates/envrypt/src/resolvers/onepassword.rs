//! 1Password `op://` secret-reference resolution (opt-in, fail-closed).
//!
//! A resolved env value of the form `op://<vault>/<item>/<field>` is replaced
//! with the secret the 1Password CLI prints for it (`op read <reference>`). The
//! ergonomic mirrors the familiar `API_KEY="op://Personal/KEY/password"` shape
//! without depending on any config file — envrypt already owns the value, so it
//! just resolves the reference at load time.
//!
//! Runs ONLY when the caller opts in (an `Exec` is threaded through
//! [`crate::resolvers::envs::ConfigOptions::op_exec`]); a stored `op://` string
//! is inert by default, so nothing shells out unless the consumer asked for it.
//!
//! FAIL-CLOSED — the deliberate opposite of the keychain provider's fail-open. A
//! reference you asked to resolve but couldn't (`op` absent, not signed in, bad
//! reference, timeout, or empty output) is an ERROR, never a silent
//! pass-through: a secret you requested but didn't get is a bug, not a default.
//!
//! Injection-safe: the reference is passed as an argv element to `op read`, never
//! interpolated into a shell. The subprocess runs behind the shared bounded
//! [`Exec`] seam, so a hung auth prompt can't wedge resolution and tests inject
//! canned output without a real `op`.

use std::time::Duration;

use indexmap::IndexMap;

use crate::providers::keychain::Exec;

/// The 1Password secret-reference scheme.
pub const OP_PREFIX: &str = "op://";

/// Default per-`op read` deadline. Longer than the keychain's 2s because `op`
/// may surface a one-time biometric / device-auth prompt the user opted into;
/// still bounded so an unanswered prompt can't wedge resolution. Tunable via
/// `ConfigOptions.op_timeout`.
pub const DEFAULT_OP_TIMEOUT: Duration = Duration::from_secs(10);

/// An `op://` resolution failure. Every variant is surfaced (fail-closed), never
/// swallowed into a silent empty or a literal pass-through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpError {
    /// `op` could not be spawned — not installed, or not on `PATH`.
    Spawn { reference: String, message: String },
    /// `op read` exited non-zero — bad reference, not signed in, or no access.
    Command {
        reference: String,
        code: Option<i32>,
    },
    /// `op read` exceeded its deadline (an unanswered auth prompt).
    Timeout { reference: String },
    /// `op read` succeeded but printed nothing — no secret to inject.
    Empty { reference: String },
}

impl OpError {
    /// The `op://` reference the failure is about.
    pub fn reference(&self) -> &str {
        match self {
            OpError::Spawn { reference, .. }
            | OpError::Command { reference, .. }
            | OpError::Timeout { reference }
            | OpError::Empty { reference } => reference,
        }
    }

    /// A human-readable message: what failed, for which reference, and how to
    /// diagnose it (rerun `op read` by hand).
    pub fn message(&self) -> String {
        let reference = self.reference();
        let cause = match self {
            OpError::Spawn { message, .. } => {
                format!("could not run the 1Password CLI (`op`): {message} — is it installed and on PATH?")
            }
            OpError::Command { code, .. } => match code {
                Some(code) => {
                    format!("`op read` exited {code} — check the reference is valid and you are signed in")
                }
                None => "`op read` was terminated by a signal".to_string(),
            },
            OpError::Timeout { .. } => {
                "`op read` exceeded its deadline — an auth prompt went unanswered".to_string()
            }
            OpError::Empty { .. } => "`op read` returned no secret".to_string(),
        };
        format!(
      "op:// resolution failed for `{reference}`: {cause}. Diagnose with: op read \"{reference}\""
    )
    }
}

/// True when `value` is a 1Password secret reference (`op://…`).
pub fn is_op_reference(value: &str) -> bool {
    value.starts_with(OP_PREFIX)
}

/// Read one `op://` reference by running `op read <reference>` through `exec`.
/// Fail-closed: a spawn error, timeout, non-zero exit, or empty output is an
/// [`OpError`]. On success the secret is returned with a single trailing
/// newline stripped (the shape `op` prints), inner content untouched.
pub fn read_op_reference(
    exec: &dyn Exec,
    reference: &str,
    timeout: Duration,
) -> Result<String, OpError> {
    let output = match exec.exec_file("op", &["read", reference, "--no-newline"], timeout) {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
            return Err(OpError::Timeout {
                reference: reference.to_string(),
            });
        }
        Err(err) => {
            return Err(OpError::Spawn {
                reference: reference.to_string(),
                message: err.to_string(),
            });
        }
    };
    if !output.status.success() {
        return Err(OpError::Command {
            reference: reference.to_string(),
            code: output.status.code(),
        });
    }
    // `op read` prints the secret followed by one newline (`\n`, or `\r\n` on
    // Windows); strip exactly that trailing line ending and keep interior bytes
    // verbatim.
    let raw = String::from_utf8_lossy(&output.stdout);
    let raw: &str = raw.as_ref();
    let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    let secret = trimmed.to_string();
    if secret.is_empty() {
        return Err(OpError::Empty {
            reference: reference.to_string(),
        });
    }
    Ok(secret)
}

/// Replace every `op://` value in `map` IN PLACE with its resolved secret,
/// via `exec`. Values that are not references are left untouched. Fail-closed:
/// the FIRST reference that fails to resolve (insertion order) returns its
/// [`OpError`]; references resolved before it are already substituted, and the
/// failing one keeps its literal `op://` value so the failure is never mistaken
/// for a real secret.
pub fn resolve_op_references(
    map: &mut IndexMap<String, String>,
    exec: &dyn Exec,
    timeout: Duration,
) -> Result<(), OpError> {
    let references: Vec<(String, String)> = map
        .iter()
        .filter(|(_, value)| is_op_reference(value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    for (key, reference) in references {
        let secret = read_op_reference(exec, &reference, timeout)?;
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
            assert_eq!(path, "op");
            assert_eq!(args, ["read", "op://Personal/KEY/password", "--no-newline"]);
            match &self.result {
                Ok(output) => Ok(output.clone()),
                Err(err) => Err(std::io::Error::new(err.kind(), err.to_string())),
            }
        }
    }

    const REF: &str = "op://Personal/KEY/password";

    #[test]
    fn is_op_reference_matches_only_the_scheme() {
        assert!(is_op_reference(REF));
        assert!(!is_op_reference("plain"));
        assert!(!is_op_reference("https://op/x"));
        assert!(!is_op_reference(""));
    }

    #[test]
    fn read_strips_one_trailing_newline() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        assert_eq!(
            read_op_reference(&exec, REF, DEFAULT_OP_TIMEOUT).unwrap(),
            "s3cr3t"
        );
    }

    #[test]
    fn read_keeps_interior_content() {
        let exec = FakeExec::ok("line1\nline2\n", 0);
        assert_eq!(
            read_op_reference(&exec, REF, DEFAULT_OP_TIMEOUT).unwrap(),
            "line1\nline2"
        );
    }

    #[test]
    fn read_fails_closed_on_nonzero_exit() {
        let exec = FakeExec::ok("", 1);
        assert_eq!(
            read_op_reference(&exec, REF, DEFAULT_OP_TIMEOUT),
            Err(OpError::Command {
                reference: REF.to_string(),
                code: Some(1),
            })
        );
    }

    #[test]
    fn read_fails_closed_on_empty_output() {
        let exec = FakeExec::ok("\n", 0);
        assert_eq!(
            read_op_reference(&exec, REF, DEFAULT_OP_TIMEOUT),
            Err(OpError::Empty {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn read_maps_spawn_failure_to_spawn_error() {
        let exec = FakeExec::err(std::io::Error::new(std::io::ErrorKind::NotFound, "no op"));
        assert!(matches!(
            read_op_reference(&exec, REF, DEFAULT_OP_TIMEOUT),
            Err(OpError::Spawn { .. })
        ));
    }

    #[test]
    fn read_maps_deadline_to_timeout_error() {
        let exec = FakeExec::err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "deadline",
        ));
        assert_eq!(
            read_op_reference(&exec, REF, DEFAULT_OP_TIMEOUT),
            Err(OpError::Timeout {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn resolve_replaces_only_op_values() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        let mut map = IndexMap::new();
        map.insert("PLAIN".to_string(), "keep".to_string());
        map.insert("SECRET".to_string(), REF.to_string());
        resolve_op_references(&mut map, &exec, DEFAULT_OP_TIMEOUT).unwrap();
        assert_eq!(map["PLAIN"], "keep");
        assert_eq!(map["SECRET"], "s3cr3t");
    }

    #[test]
    fn resolve_is_a_noop_without_references() {
        let exec = FakeExec::ok("unused\n", 0);
        let mut map = IndexMap::new();
        map.insert("A".to_string(), "1".to_string());
        resolve_op_references(&mut map, &exec, DEFAULT_OP_TIMEOUT).unwrap();
        assert_eq!(map["A"], "1");
    }

    #[test]
    fn op_error_message_names_reference_and_diagnosis() {
        let msg = OpError::Empty {
            reference: REF.to_string(),
        }
        .message();
        assert!(msg.contains(REF));
        assert!(msg.contains("op read"));
    }

    #[test]
    fn op_error_message_covers_every_variant() {
        let spawn = OpError::Spawn {
            reference: REF.to_string(),
            message: "no op".to_string(),
        }
        .message();
        assert!(spawn.contains(REF));
        assert!(spawn.contains("1Password CLI"));

        let command_code = OpError::Command {
            reference: REF.to_string(),
            code: Some(2),
        }
        .message();
        assert!(command_code.contains("exited 2"));

        let command_signal = OpError::Command {
            reference: REF.to_string(),
            code: None,
        }
        .message();
        assert!(command_signal.contains("signal"));

        let timeout = OpError::Timeout {
            reference: REF.to_string(),
        }
        .message();
        assert!(timeout.contains("deadline"));
    }
}
