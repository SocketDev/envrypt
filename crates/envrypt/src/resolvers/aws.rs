//! AWS Secrets Manager `aws://` secret-reference resolution (opt-in,
//! fail-closed).
//!
//! A resolved env value of the form `aws://<secret-id>` is replaced with the
//! secret the AWS CLI prints for it (`aws secretsmanager get-secret-value
//! --secret-id <id> --query SecretString --output text`). The `<secret-id>` is
//! the secret's name or ARN, mirroring the familiar
//! `API_KEY="aws://prod/db-password"` shape, the companion to
//! [`super::bitwarden`].
//!
//! Runs ONLY when the caller opts in (an `Exec` is threaded through
//! [`crate::resolvers::envs::ConfigOptions::aws_exec`]); a stored `aws://` string
//! is inert by default, so nothing shells out unless the consumer asked for it.
//!
//! SESSION — `aws` reads credentials from the standard chain (`AWS_PROFILE`, env
//! keys, SSO), which the spawned child inherits from this process. An
//! unauthenticated CLI exits non-zero, which surfaces as a fail-closed
//! [`AwsError::Command`] — never a silent miss.
//!
//! FAIL-CLOSED — the deliberate opposite of the keychain provider's fail-open. A
//! reference you asked to resolve but couldn't (`aws` absent, not authenticated,
//! bad reference, timeout, or empty output) is an ERROR, never a silent
//! pass-through: a secret you requested but didn't get is a bug, not a default.
//!
//! Injection-safe: the secret id is passed as an argv element to `aws
//! secretsmanager get-secret-value`, never interpolated into a shell. The
//! subprocess runs behind the shared bounded [`Exec`] seam, so a hung CLI can't
//! wedge resolution and tests inject canned output without a real `aws`.
//!
//! Docs: <https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/get-secret-value.html>

use std::time::Duration;

use indexmap::IndexMap;

use crate::providers::keychain::Exec;

/// The AWS Secrets Manager secret-reference scheme.
pub const AWS_PREFIX: &str = "aws://";

/// Default per-`aws secretsmanager get-secret-value` deadline. Matches the other
/// resolvers' 10 s — a bounded window that tolerates a slow API round-trip
/// without wedging resolution. Tunable via `ConfigOptions.aws_timeout`.
pub const DEFAULT_AWS_TIMEOUT: Duration = Duration::from_secs(10);

/// An `aws://` resolution failure. Every variant is surfaced (fail-closed), never
/// swallowed into a silent empty or a literal pass-through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwsError {
    /// `aws` could not be spawned — not installed, or not on `PATH`.
    Spawn { reference: String, message: String },
    /// `aws secretsmanager get-secret-value` exited non-zero — not authenticated,
    /// bad secret id, or no access.
    Command {
        reference: String,
        code: Option<i32>,
    },
    /// `aws secretsmanager get-secret-value` exceeded its deadline.
    Timeout { reference: String },
    /// `aws secretsmanager get-secret-value` succeeded but printed nothing — no
    /// secret to inject.
    Empty { reference: String },
    /// The reference is not `aws://<secret-id>`.
    InvalidReference { reference: String },
}

impl AwsError {
    /// The `aws://` reference the failure is about.
    pub fn reference(&self) -> &str {
        match self {
            AwsError::Spawn { reference, .. }
            | AwsError::Command { reference, .. }
            | AwsError::Timeout { reference }
            | AwsError::Empty { reference }
            | AwsError::InvalidReference { reference } => reference,
        }
    }

    /// A human-readable message: what failed, for which reference, and how to
    /// diagnose it.
    pub fn message(&self) -> String {
        let reference = self.reference();
        let cause = match self {
      AwsError::Spawn { message, .. } => {
        format!("could not run the AWS CLI (`aws`): {message} — is it installed and on PATH?")
      }
      AwsError::Command { code, .. } => match code {
        Some(code) => format!(
          "`aws secretsmanager get-secret-value` exited {code} — authenticate the CLI (the AWS credential chain) and check the secret id"
        ),
        None => "`aws secretsmanager get-secret-value` was terminated by a signal".to_string(),
      },
      AwsError::Timeout { .. } => {
        "`aws secretsmanager get-secret-value` exceeded its deadline".to_string()
      }
      AwsError::Empty { .. } => {
        "`aws secretsmanager get-secret-value` returned no secret".to_string()
      }
      AwsError::InvalidReference { .. } => "not an `aws://<secret-id>` reference".to_string(),
    };
        format!("aws:// resolution failed for `{reference}`: {cause}.")
    }
}

/// True when `value` is an AWS Secrets Manager secret reference (`aws://…`).
pub fn is_aws_reference(value: &str) -> bool {
    value.starts_with(AWS_PREFIX)
}

/// Parse `aws://<secret-id>` into its `secret_id`. The remainder after the scheme
/// is the secret's name or ARN and must be non-empty.
pub fn parse_aws_reference(reference: &str) -> Result<String, AwsError> {
    let secret_id = reference.strip_prefix(AWS_PREFIX).unwrap_or(reference);
    if secret_id.is_empty() {
        return Err(AwsError::InvalidReference {
            reference: reference.to_string(),
        });
    }
    Ok(secret_id.to_string())
}

/// Read one `aws://` reference by running `aws secretsmanager get-secret-value
/// --secret-id <id> --query SecretString --output text` through `exec`.
/// Fail-closed: a bad reference, spawn error, timeout, non-zero exit, or empty
/// output is an [`AwsError`]. On success the secret is returned with a single
/// trailing newline stripped, inner content untouched.
pub fn read_aws_reference(
    exec: &dyn Exec,
    reference: &str,
    timeout: Duration,
) -> Result<String, AwsError> {
    let secret_id = parse_aws_reference(reference)?;
    let output = match exec.exec_file(
        "aws",
        &[
            "secretsmanager",
            "get-secret-value",
            "--secret-id",
            &secret_id,
            "--query",
            "SecretString",
            "--output",
            "text",
        ],
        timeout,
    ) {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
            return Err(AwsError::Timeout {
                reference: reference.to_string(),
            });
        }
        Err(err) => {
            return Err(AwsError::Spawn {
                reference: reference.to_string(),
                message: err.to_string(),
            });
        }
    };
    if !output.status.success() {
        return Err(AwsError::Command {
            reference: reference.to_string(),
            code: output.status.code(),
        });
    }
    // `--output text` prints the secret string followed by one newline (`\n`, or
    // `\r\n` on Windows); strip exactly that trailing line ending and keep interior
    // bytes.
    let raw = String::from_utf8_lossy(&output.stdout);
    let raw: &str = raw.as_ref();
    let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    let secret = trimmed.to_string();
    if secret.is_empty() {
        return Err(AwsError::Empty {
            reference: reference.to_string(),
        });
    }
    Ok(secret)
}

/// Replace every `aws://` value in `map` IN PLACE with its resolved secret, via
/// `exec`. Values that are not references are left untouched. Fail-closed: the
/// FIRST reference that fails to resolve (insertion order) returns its
/// [`AwsError`]; references resolved before it are already substituted, and the
/// failing one keeps its literal `aws://` value so the failure is never mistaken
/// for a real secret.
pub fn resolve_aws_references(
    map: &mut IndexMap<String, String>,
    exec: &dyn Exec,
    timeout: Duration,
) -> Result<(), AwsError> {
    let references: Vec<(String, String)> = map
        .iter()
        .filter(|(_, value)| is_aws_reference(value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    for (key, reference) in references {
        let secret = read_aws_reference(exec, &reference, timeout)?;
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
            assert_eq!(path, "aws");
            assert_eq!(
                args,
                [
                    "secretsmanager",
                    "get-secret-value",
                    "--secret-id",
                    SECRET_ID,
                    "--query",
                    "SecretString",
                    "--output",
                    "text",
                ]
            );
            match &self.result {
                Ok(output) => Ok(output.clone()),
                Err(err) => Err(std::io::Error::new(err.kind(), err.to_string())),
            }
        }
    }

    const SECRET_ID: &str = "prod/db-password";
    const REF: &str = "aws://prod/db-password";

    #[test]
    fn is_aws_reference_matches_only_the_scheme() {
        assert!(is_aws_reference(REF));
        assert!(!is_aws_reference("plain"));
        assert!(!is_aws_reference("bw://x/password"));
        assert!(!is_aws_reference(""));
    }

    #[test]
    fn parse_accepts_a_secret_id() {
        assert_eq!(parse_aws_reference(REF).unwrap(), SECRET_ID.to_string());
    }

    #[test]
    fn parse_rejects_an_empty_secret_id() {
        // `aws://` — the scheme with no secret id after it.
        assert!(matches!(
            parse_aws_reference("aws://"),
            Err(AwsError::InvalidReference { .. })
        ));
    }

    #[test]
    fn read_strips_one_trailing_newline() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        assert_eq!(
            read_aws_reference(&exec, REF, DEFAULT_AWS_TIMEOUT).unwrap(),
            "s3cr3t"
        );
    }

    #[test]
    fn read_fails_closed_on_unauthenticated_nonzero_exit() {
        let exec = FakeExec::ok("", 255);
        assert_eq!(
            read_aws_reference(&exec, REF, DEFAULT_AWS_TIMEOUT),
            Err(AwsError::Command {
                reference: REF.to_string(),
                code: Some(255),
            })
        );
    }

    #[test]
    fn read_maps_spawn_failure_to_spawn_error() {
        let exec = FakeExec::err(std::io::Error::new(std::io::ErrorKind::NotFound, "no aws"));
        assert!(matches!(
            read_aws_reference(&exec, REF, DEFAULT_AWS_TIMEOUT),
            Err(AwsError::Spawn { .. })
        ));
    }

    #[test]
    fn read_maps_deadline_to_timeout_error() {
        let exec = FakeExec::err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "deadline",
        ));
        assert_eq!(
            read_aws_reference(&exec, REF, DEFAULT_AWS_TIMEOUT),
            Err(AwsError::Timeout {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn read_fails_closed_on_empty_output() {
        let exec = FakeExec::ok("\n", 0);
        assert_eq!(
            read_aws_reference(&exec, REF, DEFAULT_AWS_TIMEOUT),
            Err(AwsError::Empty {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn read_keeps_interior_content() {
        let exec = FakeExec::ok("line1\nline2\n", 0);
        assert_eq!(
            read_aws_reference(&exec, REF, DEFAULT_AWS_TIMEOUT).unwrap(),
            "line1\nline2"
        );
    }

    #[test]
    fn resolve_replaces_only_aws_values() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        let mut map = IndexMap::new();
        map.insert("PLAIN".to_string(), "keep".to_string());
        map.insert("SECRET".to_string(), REF.to_string());
        resolve_aws_references(&mut map, &exec, DEFAULT_AWS_TIMEOUT).unwrap();
        assert_eq!(map["PLAIN"], "keep");
        assert_eq!(map["SECRET"], "s3cr3t");
    }

    #[test]
    fn resolve_is_a_noop_without_references() {
        let exec = FakeExec::ok("unused\n", 0);
        let mut map = IndexMap::new();
        map.insert("A".to_string(), "1".to_string());
        resolve_aws_references(&mut map, &exec, DEFAULT_AWS_TIMEOUT).unwrap();
        assert_eq!(map["A"], "1");
    }

    #[test]
    fn aws_error_message_names_reference() {
        let msg = AwsError::Empty {
            reference: REF.to_string(),
        }
        .message();
        assert!(msg.contains(REF));
        assert!(msg.contains("get-secret-value"));
    }

    #[test]
    fn aws_error_message_covers_every_variant() {
        let spawn = AwsError::Spawn {
            reference: REF.to_string(),
            message: "no aws".to_string(),
        }
        .message();
        assert!(spawn.contains(REF));
        assert!(spawn.contains("AWS CLI"));

        let command_code = AwsError::Command {
            reference: REF.to_string(),
            code: Some(2),
        }
        .message();
        assert!(command_code.contains("exited 2"));

        let command_signal = AwsError::Command {
            reference: REF.to_string(),
            code: None,
        }
        .message();
        assert!(command_signal.contains("signal"));

        let timeout = AwsError::Timeout {
            reference: REF.to_string(),
        }
        .message();
        assert!(timeout.contains("deadline"));

        let empty = AwsError::Empty {
            reference: REF.to_string(),
        }
        .message();
        assert!(empty.contains("no secret"));

        let invalid = AwsError::InvalidReference {
            reference: REF.to_string(),
        }
        .message();
        assert!(invalid.contains("aws://<secret-id>"));
    }
}
