//! GCP Secret Manager `gcp://` secret-reference resolution (opt-in,
//! fail-closed).
//!
//! A resolved env value of the form `gcp://<name>` is replaced with the secret
//! the `gcloud` CLI prints for it (`gcloud secrets versions access latest
//! --secret=<name>`). The `<name>` is the secret's name, mirroring the familiar
//! `API_KEY="gcp://api-key"` shape, the companion to [`super::bitwarden`].
//!
//! Runs ONLY when the caller opts in (an `Exec` is threaded through
//! [`crate::resolvers::envs::ConfigOptions::gcp_exec`]); a stored `gcp://` string
//! is inert by default, so nothing shells out unless the consumer asked for it.
//!
//! SESSION — `gcloud` reads its application-default credentials from `gcloud
//! auth` in the process environment, which the spawned child inherits from this
//! process. An unauthenticated CLI exits non-zero, which surfaces as a
//! fail-closed [`GcpError::Command`] — never a silent miss.
//!
//! FAIL-CLOSED — the deliberate opposite of the keychain provider's fail-open. A
//! reference you asked to resolve but couldn't (`gcloud` absent, not
//! authenticated, bad reference, timeout, or empty output) is an ERROR, never a
//! silent pass-through: a secret you requested but didn't get is a bug, not a
//! default.
//!
//! Injection-safe: the name is passed as an argv element to `gcloud secrets
//! versions access`, never interpolated into a shell. The subprocess runs behind
//! the shared bounded [`Exec`] seam, so a hung CLI can't wedge resolution and
//! tests inject canned output without a real `gcloud`.
//!
//! Docs: <https://docs.cloud.google.com/sdk/gcloud/reference/secrets/versions/access>

use std::time::Duration;

use indexmap::IndexMap;

use crate::providers::keychain::Exec;

/// The GCP Secret Manager secret-reference scheme.
pub const GCP_PREFIX: &str = "gcp://";

/// Default per-`gcloud secrets versions access` deadline. Matches the other
/// resolvers' 10 s — a bounded window that tolerates a slow API round-trip
/// without wedging resolution. Tunable via `ConfigOptions.gcp_timeout`.
pub const DEFAULT_GCP_TIMEOUT: Duration = Duration::from_secs(10);

/// A `gcp://` resolution failure. Every variant is surfaced (fail-closed), never
/// swallowed into a silent empty or a literal pass-through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcpError {
    /// `gcloud` could not be spawned — not installed, or not on `PATH`.
    Spawn { reference: String, message: String },
    /// `gcloud secrets versions access` exited non-zero — not authenticated, bad
    /// name, or no access.
    Command {
        reference: String,
        code: Option<i32>,
    },
    /// `gcloud secrets versions access` exceeded its deadline.
    Timeout { reference: String },
    /// `gcloud secrets versions access` succeeded but printed nothing — no secret
    /// to inject.
    Empty { reference: String },
    /// The reference is not `gcp://<name>`.
    InvalidReference { reference: String },
}

impl GcpError {
    /// The `gcp://` reference the failure is about.
    pub fn reference(&self) -> &str {
        match self {
            GcpError::Spawn { reference, .. }
            | GcpError::Command { reference, .. }
            | GcpError::Timeout { reference }
            | GcpError::Empty { reference }
            | GcpError::InvalidReference { reference } => reference,
        }
    }

    /// A human-readable message: what failed, for which reference, and how to
    /// diagnose it.
    pub fn message(&self) -> String {
        let reference = self.reference();
        let cause = match self {
      GcpError::Spawn { message, .. } => {
        format!("could not run the gcloud CLI (`gcloud`): {message} — is it installed and on PATH?")
      }
      GcpError::Command { code, .. } => match code {
        Some(code) => format!(
          "`gcloud secrets versions access` exited {code} — authenticate the CLI (`gcloud auth`) and check the name"
        ),
        None => "`gcloud secrets versions access` was terminated by a signal".to_string(),
      },
      GcpError::Timeout { .. } => {
        "`gcloud secrets versions access` exceeded its deadline".to_string()
      }
      GcpError::Empty { .. } => "`gcloud secrets versions access` returned no secret".to_string(),
      GcpError::InvalidReference { .. } => "not a `gcp://<name>` reference".to_string(),
    };
        format!("gcp:// resolution failed for `{reference}`: {cause}.")
    }
}

/// True when `value` is a GCP Secret Manager secret reference (`gcp://…`).
pub fn is_gcp_reference(value: &str) -> bool {
    value.starts_with(GCP_PREFIX)
}

/// Parse `gcp://<name>` into its `name`. The remainder after the scheme is the
/// secret's name and must be non-empty.
pub fn parse_gcp_reference(reference: &str) -> Result<String, GcpError> {
    let name = reference.strip_prefix(GCP_PREFIX).unwrap_or(reference);
    if name.is_empty() {
        return Err(GcpError::InvalidReference {
            reference: reference.to_string(),
        });
    }
    Ok(name.to_string())
}

/// Read one `gcp://` reference by running `gcloud secrets versions access latest
/// --secret=<name>` through `exec`. Fail-closed: a bad reference, spawn error,
/// timeout, non-zero exit, or empty output is a [`GcpError`]. On success the
/// secret is returned with a single trailing newline stripped, inner content
/// untouched.
pub fn read_gcp_reference(
    exec: &dyn Exec,
    reference: &str,
    timeout: Duration,
) -> Result<String, GcpError> {
    let name = parse_gcp_reference(reference)?;
    let secret_arg = format!("--secret={name}");
    let output = match exec.exec_file(
        "gcloud",
        &["secrets", "versions", "access", "latest", &secret_arg],
        timeout,
    ) {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
            return Err(GcpError::Timeout {
                reference: reference.to_string(),
            });
        }
        Err(err) => {
            return Err(GcpError::Spawn {
                reference: reference.to_string(),
                message: err.to_string(),
            });
        }
    };
    if !output.status.success() {
        return Err(GcpError::Command {
            reference: reference.to_string(),
            code: output.status.code(),
        });
    }
    // `gcloud secrets versions access` prints the payload followed by one newline
    // (`\n`, or `\r\n` on Windows); strip exactly that trailing line ending and
    // keep interior bytes.
    let raw = String::from_utf8_lossy(&output.stdout);
    let raw: &str = raw.as_ref();
    let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    let secret = trimmed.to_string();
    if secret.is_empty() {
        return Err(GcpError::Empty {
            reference: reference.to_string(),
        });
    }
    Ok(secret)
}

/// Replace every `gcp://` value in `map` IN PLACE with its resolved secret, via
/// `exec`. Values that are not references are left untouched. Fail-closed: the
/// FIRST reference that fails to resolve (insertion order) returns its
/// [`GcpError`]; references resolved before it are already substituted, and the
/// failing one keeps its literal `gcp://` value so the failure is never mistaken
/// for a real secret.
pub fn resolve_gcp_references(
    map: &mut IndexMap<String, String>,
    exec: &dyn Exec,
    timeout: Duration,
) -> Result<(), GcpError> {
    let references: Vec<(String, String)> = map
        .iter()
        .filter(|(_, value)| is_gcp_reference(value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    for (key, reference) in references {
        let secret = read_gcp_reference(exec, &reference, timeout)?;
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
            assert_eq!(path, "gcloud");
            assert_eq!(
                args,
                [
                    "secrets",
                    "versions",
                    "access",
                    "latest",
                    "--secret=api-key"
                ]
            );
            match &self.result {
                Ok(output) => Ok(output.clone()),
                Err(err) => Err(std::io::Error::new(err.kind(), err.to_string())),
            }
        }
    }

    const REF: &str = "gcp://api-key";

    #[test]
    fn is_gcp_reference_matches_only_the_scheme() {
        assert!(is_gcp_reference(REF));
        assert!(!is_gcp_reference("plain"));
        assert!(!is_gcp_reference("bw://x/password"));
        assert!(!is_gcp_reference(""));
    }

    #[test]
    fn parse_accepts_a_name() {
        assert_eq!(parse_gcp_reference(REF).unwrap(), "api-key".to_string());
    }

    #[test]
    fn parse_rejects_an_empty_name() {
        // `gcp://` — the scheme with no name after it.
        assert!(matches!(
            parse_gcp_reference("gcp://"),
            Err(GcpError::InvalidReference { .. })
        ));
    }

    #[test]
    fn read_strips_one_trailing_newline() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        assert_eq!(
            read_gcp_reference(&exec, REF, DEFAULT_GCP_TIMEOUT).unwrap(),
            "s3cr3t"
        );
    }

    #[test]
    fn read_fails_closed_on_unauthenticated_nonzero_exit() {
        let exec = FakeExec::ok("", 1);
        assert_eq!(
            read_gcp_reference(&exec, REF, DEFAULT_GCP_TIMEOUT),
            Err(GcpError::Command {
                reference: REF.to_string(),
                code: Some(1),
            })
        );
    }

    #[test]
    fn read_maps_spawn_failure_to_spawn_error() {
        let exec = FakeExec::err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no gcloud",
        ));
        assert!(matches!(
            read_gcp_reference(&exec, REF, DEFAULT_GCP_TIMEOUT),
            Err(GcpError::Spawn { .. })
        ));
    }

    #[test]
    fn read_maps_deadline_to_timeout_error() {
        let exec = FakeExec::err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "deadline",
        ));
        assert_eq!(
            read_gcp_reference(&exec, REF, DEFAULT_GCP_TIMEOUT),
            Err(GcpError::Timeout {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn read_fails_closed_on_empty_output() {
        let exec = FakeExec::ok("\n", 0);
        assert_eq!(
            read_gcp_reference(&exec, REF, DEFAULT_GCP_TIMEOUT),
            Err(GcpError::Empty {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn read_keeps_interior_content() {
        let exec = FakeExec::ok("line1\nline2\n", 0);
        assert_eq!(
            read_gcp_reference(&exec, REF, DEFAULT_GCP_TIMEOUT).unwrap(),
            "line1\nline2"
        );
    }

    #[test]
    fn resolve_replaces_only_gcp_values() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        let mut map = IndexMap::new();
        map.insert("PLAIN".to_string(), "keep".to_string());
        map.insert("SECRET".to_string(), REF.to_string());
        resolve_gcp_references(&mut map, &exec, DEFAULT_GCP_TIMEOUT).unwrap();
        assert_eq!(map["PLAIN"], "keep");
        assert_eq!(map["SECRET"], "s3cr3t");
    }

    #[test]
    fn resolve_is_a_noop_without_references() {
        let exec = FakeExec::ok("unused\n", 0);
        let mut map = IndexMap::new();
        map.insert("A".to_string(), "1".to_string());
        resolve_gcp_references(&mut map, &exec, DEFAULT_GCP_TIMEOUT).unwrap();
        assert_eq!(map["A"], "1");
    }

    #[test]
    fn gcp_error_message_names_reference() {
        let msg = GcpError::Empty {
            reference: REF.to_string(),
        }
        .message();
        assert!(msg.contains(REF));
        assert!(msg.contains("gcloud secrets versions access"));
    }

    #[test]
    fn gcp_error_message_covers_every_variant() {
        let spawn = GcpError::Spawn {
            reference: REF.to_string(),
            message: "no gcloud".to_string(),
        }
        .message();
        assert!(spawn.contains(REF));
        assert!(spawn.contains("gcloud CLI"));

        let command_code = GcpError::Command {
            reference: REF.to_string(),
            code: Some(2),
        }
        .message();
        assert!(command_code.contains("exited 2"));

        let command_signal = GcpError::Command {
            reference: REF.to_string(),
            code: None,
        }
        .message();
        assert!(command_signal.contains("signal"));

        let timeout = GcpError::Timeout {
            reference: REF.to_string(),
        }
        .message();
        assert!(timeout.contains("deadline"));

        let empty = GcpError::Empty {
            reference: REF.to_string(),
        }
        .message();
        assert!(empty.contains("no secret"));

        let invalid = GcpError::InvalidReference {
            reference: REF.to_string(),
        }
        .message();
        assert!(invalid.contains("gcp://<name>"));
    }
}
