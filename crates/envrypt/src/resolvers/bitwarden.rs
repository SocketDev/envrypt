//! Bitwarden `bw://` secret-reference resolution (opt-in, fail-closed).
//!
//! A resolved env value of the form `bw://<item-uuid>/<field>` is replaced with
//! the secret the Bitwarden CLI prints for it (`bw get <field> <item-uuid>`). The
//! `<field>` is one of `username`, `password`, or `uri`; the `<item-uuid>` is the
//! item's canonical UUID. The ergonomic mirrors the familiar
//! `API_KEY="bw://<uuid>/password"` shape, the companion to [`super::onepassword`].
//!
//! Runs ONLY when the caller opts in (an `Exec` is threaded through
//! [`crate::resolvers::envs::ConfigOptions::bw_exec`]); a stored `bw://` string is
//! inert by default, so nothing shells out unless the consumer asked for it.
//!
//! SESSION — `bw` reads the unlocked vault session from the `BW_SESSION`
//! environment variable, which the spawned child inherits from this process. A
//! locked vault (`BW_SESSION` unset or expired) makes `bw get` exit non-zero,
//! which surfaces as a fail-closed [`BwError::Command`] — never a silent miss.
//!
//! FAIL-CLOSED — the deliberate opposite of the keychain provider's fail-open. A
//! reference you asked to resolve but couldn't (`bw` absent, vault locked, bad
//! reference or field, timeout, or empty output) is an ERROR, never a silent
//! pass-through: a secret you requested but didn't get is a bug, not a default.
//!
//! Injection-safe: the item id + field are passed as argv elements to `bw get`,
//! never interpolated into a shell. The subprocess runs behind the shared bounded
//! [`Exec`] seam, so a hung vault prompt can't wedge resolution and tests inject
//! canned output without a real `bw`.

use std::time::Duration;

use indexmap::IndexMap;

use crate::providers::keychain::Exec;

/// The Bitwarden secret-reference scheme.
pub const BW_PREFIX: &str = "bw://";

/// Default per-`bw get` deadline. Matches the 1Password resolver's 10 s — a
/// bounded window that tolerates a slow vault sync without wedging resolution.
/// Tunable via `ConfigOptions.bw_timeout`.
pub const DEFAULT_BW_TIMEOUT: Duration = Duration::from_secs(10);

/// The Bitwarden item fields a `bw://` reference may name (sorted).
const FIELDS: [&str; 3] = ["password", "uri", "username"];

/// True when `s` is a canonical 8-4-4-4-12 hex UUID (either case).
fn is_uuid(s: &str) -> bool {
    let groups = [8_usize, 4, 4, 4, 12];
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != groups.len() {
        return false;
    }
    for (i, part) in parts.iter().enumerate() {
        if part.len() != groups[i] || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

/// A `bw://` resolution failure. Every variant is surfaced (fail-closed), never
/// swallowed into a silent empty or a literal pass-through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BwError {
    /// `bw` could not be spawned — not installed, or not on `PATH`.
    Spawn { reference: String, message: String },
    /// `bw get` exited non-zero — vault locked (no `BW_SESSION`), bad id, or no access.
    Command {
        reference: String,
        code: Option<i32>,
    },
    /// `bw get` exceeded its deadline.
    Timeout { reference: String },
    /// `bw get` succeeded but printed nothing — no secret to inject.
    Empty { reference: String },
    /// The reference is not `bw://<uuid>/<field>`.
    InvalidReference { reference: String },
    /// The `<field>` is not one of `username`, `password`, `uri`.
    UnsupportedField { reference: String, field: String },
}

impl BwError {
    /// The `bw://` reference the failure is about.
    pub fn reference(&self) -> &str {
        match self {
            BwError::Spawn { reference, .. }
            | BwError::Command { reference, .. }
            | BwError::Timeout { reference }
            | BwError::Empty { reference }
            | BwError::InvalidReference { reference }
            | BwError::UnsupportedField { reference, .. } => reference,
        }
    }

    /// A human-readable message: what failed, for which reference, and how to
    /// diagnose it.
    pub fn message(&self) -> String {
        let reference = self.reference();
        let cause = match self {
      BwError::Spawn { message, .. } => {
        format!("could not run the Bitwarden CLI (`bw`): {message} — is it installed and on PATH?")
      }
      BwError::Command { code, .. } => match code {
        Some(code) => format!(
          "`bw get` exited {code} — unlock the vault (`export BW_SESSION=\"$(bw unlock --raw)\"`) and check the item id"
        ),
        None => "`bw get` was terminated by a signal".to_string(),
      },
      BwError::Timeout { .. } => "`bw get` exceeded its deadline".to_string(),
      BwError::Empty { .. } => "`bw get` returned no secret".to_string(),
      BwError::InvalidReference { .. } => {
        "not a `bw://<item-uuid>/<field>` reference".to_string()
      }
      BwError::UnsupportedField { field, .. } => {
        format!("unsupported field `{field}` — use one of username, password, uri")
      }
    };
        format!("bw:// resolution failed for `{reference}`: {cause}.")
    }
}

/// True when `value` is a Bitwarden secret reference (`bw://…`).
pub fn is_bw_reference(value: &str) -> bool {
    value.starts_with(BW_PREFIX)
}

/// Parse `bw://<item-uuid>/<field>` into its `(item_id, field)`. The id must be a
/// canonical UUID and the field one of `username`/`password`/`uri`.
pub fn parse_bw_reference(reference: &str) -> Result<(String, String), BwError> {
    let rest = reference.strip_prefix(BW_PREFIX).unwrap_or(reference);
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 2 {
        return Err(BwError::InvalidReference {
            reference: reference.to_string(),
        });
    }
    let (item_id, field) = (parts[0], parts[1]);
    if !is_uuid(item_id) || field.is_empty() {
        return Err(BwError::InvalidReference {
            reference: reference.to_string(),
        });
    }
    if !FIELDS.contains(&field) {
        return Err(BwError::UnsupportedField {
            reference: reference.to_string(),
            field: field.to_string(),
        });
    }
    Ok((item_id.to_string(), field.to_string()))
}

/// Read one `bw://` reference by running `bw get <field> <item-uuid>` through
/// `exec`. Fail-closed: a bad reference, spawn error, timeout, non-zero exit, or
/// empty output is a [`BwError`]. On success the secret is returned with a single
/// trailing newline stripped, inner content untouched.
pub fn read_bw_reference(
    exec: &dyn Exec,
    reference: &str,
    timeout: Duration,
) -> Result<String, BwError> {
    let (item_id, field) = parse_bw_reference(reference)?;
    let output = match exec.exec_file("bw", &["get", &field, &item_id], timeout) {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
            return Err(BwError::Timeout {
                reference: reference.to_string(),
            });
        }
        Err(err) => {
            return Err(BwError::Spawn {
                reference: reference.to_string(),
                message: err.to_string(),
            });
        }
    };
    if !output.status.success() {
        return Err(BwError::Command {
            reference: reference.to_string(),
            code: output.status.code(),
        });
    }
    // `bw get` prints the secret followed by one newline (`\n`, or `\r\n` on
    // Windows); strip exactly that trailing line ending and keep interior bytes.
    let raw = String::from_utf8_lossy(&output.stdout);
    let raw: &str = raw.as_ref();
    let trimmed = raw.strip_suffix('\n').unwrap_or(raw);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    let secret = trimmed.to_string();
    if secret.is_empty() {
        return Err(BwError::Empty {
            reference: reference.to_string(),
        });
    }
    Ok(secret)
}

/// Replace every `bw://` value in `map` IN PLACE with its resolved secret, via
/// `exec`. Values that are not references are left untouched. Fail-closed: the
/// FIRST reference that fails to resolve (insertion order) returns its
/// [`BwError`]; references resolved before it are already substituted, and the
/// failing one keeps its literal `bw://` value so the failure is never mistaken
/// for a real secret.
pub fn resolve_bw_references(
    map: &mut IndexMap<String, String>,
    exec: &dyn Exec,
    timeout: Duration,
) -> Result<(), BwError> {
    let references: Vec<(String, String)> = map
        .iter()
        .filter(|(_, value)| is_bw_reference(value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    for (key, reference) in references {
        let secret = read_bw_reference(exec, &reference, timeout)?;
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
            assert_eq!(path, "bw");
            assert_eq!(args, ["get", "password", UUID]);
            match &self.result {
                Ok(output) => Ok(output.clone()),
                Err(err) => Err(std::io::Error::new(err.kind(), err.to_string())),
            }
        }
    }

    const UUID: &str = "12345678-1234-1234-1234-123456789abc";
    const REF: &str = "bw://12345678-1234-1234-1234-123456789abc/password";

    #[test]
    fn is_bw_reference_matches_only_the_scheme() {
        assert!(is_bw_reference(REF));
        assert!(!is_bw_reference("plain"));
        assert!(!is_bw_reference("op://Personal/x/password"));
        assert!(!is_bw_reference(""));
    }

    #[test]
    fn parse_accepts_a_uuid_and_known_field() {
        assert_eq!(
            parse_bw_reference(REF).unwrap(),
            (UUID.to_string(), "password".to_string())
        );
    }

    #[test]
    fn parse_rejects_a_non_uuid_item() {
        assert!(matches!(
            parse_bw_reference("bw://not-a-uuid/password"),
            Err(BwError::InvalidReference { .. })
        ));
    }

    #[test]
    fn parse_rejects_an_extra_path_segment() {
        assert!(matches!(
            parse_bw_reference(&format!("bw://{UUID}/password/extra")),
            Err(BwError::InvalidReference { .. })
        ));
    }

    #[test]
    fn parse_rejects_an_unsupported_field() {
        assert!(matches!(
            parse_bw_reference(&format!("bw://{UUID}/totp")),
            Err(BwError::UnsupportedField { .. })
        ));
    }

    #[test]
    fn parse_rejects_an_empty_field() {
        // `bw://<uuid>/` — a valid item id but no field after the slash.
        assert!(matches!(
            parse_bw_reference(&format!("bw://{UUID}/")),
            Err(BwError::InvalidReference { .. })
        ));
    }

    #[test]
    fn is_uuid_rejects_malformed_shapes() {
        assert!(is_uuid(UUID));
        // Wrong group count (too few / too many `-`-separated groups).
        assert!(!is_uuid("12345678-1234-1234-1234"));
        assert!(!is_uuid("12345678-1234-1234-1234-123456789abc-abcd"));
        // Wrong group length (first group one char short).
        assert!(!is_uuid("1234567-1234-1234-1234-123456789abc"));
        // Non-hex character in a group.
        assert!(!is_uuid("1234567g-1234-1234-1234-123456789abc"));
    }

    #[test]
    fn read_strips_one_trailing_newline() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        assert_eq!(
            read_bw_reference(&exec, REF, DEFAULT_BW_TIMEOUT).unwrap(),
            "s3cr3t"
        );
    }

    #[test]
    fn read_fails_closed_on_locked_vault_nonzero_exit() {
        let exec = FakeExec::ok("", 1);
        assert_eq!(
            read_bw_reference(&exec, REF, DEFAULT_BW_TIMEOUT),
            Err(BwError::Command {
                reference: REF.to_string(),
                code: Some(1),
            })
        );
    }

    #[test]
    fn read_maps_spawn_failure_to_spawn_error() {
        let exec = FakeExec::err(std::io::Error::new(std::io::ErrorKind::NotFound, "no bw"));
        assert!(matches!(
            read_bw_reference(&exec, REF, DEFAULT_BW_TIMEOUT),
            Err(BwError::Spawn { .. })
        ));
    }

    #[test]
    fn read_maps_deadline_to_timeout_error() {
        let exec = FakeExec::err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "deadline",
        ));
        assert_eq!(
            read_bw_reference(&exec, REF, DEFAULT_BW_TIMEOUT),
            Err(BwError::Timeout {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn read_fails_closed_on_empty_output() {
        let exec = FakeExec::ok("\n", 0);
        assert_eq!(
            read_bw_reference(&exec, REF, DEFAULT_BW_TIMEOUT),
            Err(BwError::Empty {
                reference: REF.to_string(),
            })
        );
    }

    #[test]
    fn read_keeps_interior_content() {
        let exec = FakeExec::ok("line1\nline2\n", 0);
        assert_eq!(
            read_bw_reference(&exec, REF, DEFAULT_BW_TIMEOUT).unwrap(),
            "line1\nline2"
        );
    }

    #[test]
    fn resolve_replaces_only_bw_values() {
        let exec = FakeExec::ok("s3cr3t\n", 0);
        let mut map = IndexMap::new();
        map.insert("PLAIN".to_string(), "keep".to_string());
        map.insert("SECRET".to_string(), REF.to_string());
        resolve_bw_references(&mut map, &exec, DEFAULT_BW_TIMEOUT).unwrap();
        assert_eq!(map["PLAIN"], "keep");
        assert_eq!(map["SECRET"], "s3cr3t");
    }

    #[test]
    fn resolve_is_a_noop_without_references() {
        let exec = FakeExec::ok("unused\n", 0);
        let mut map = IndexMap::new();
        map.insert("A".to_string(), "1".to_string());
        resolve_bw_references(&mut map, &exec, DEFAULT_BW_TIMEOUT).unwrap();
        assert_eq!(map["A"], "1");
    }

    #[test]
    fn bw_error_message_names_reference() {
        let msg = BwError::Empty {
            reference: REF.to_string(),
        }
        .message();
        assert!(msg.contains(REF));
        assert!(msg.contains("bw get"));
    }

    #[test]
    fn bw_error_message_covers_every_variant() {
        let spawn = BwError::Spawn {
            reference: REF.to_string(),
            message: "no bw".to_string(),
        }
        .message();
        assert!(spawn.contains(REF));
        assert!(spawn.contains("Bitwarden CLI"));

        let command_code = BwError::Command {
            reference: REF.to_string(),
            code: Some(2),
        }
        .message();
        assert!(command_code.contains("exited 2"));

        let command_signal = BwError::Command {
            reference: REF.to_string(),
            code: None,
        }
        .message();
        assert!(command_signal.contains("signal"));

        let timeout = BwError::Timeout {
            reference: REF.to_string(),
        }
        .message();
        assert!(timeout.contains("deadline"));

        let empty = BwError::Empty {
            reference: REF.to_string(),
        }
        .message();
        assert!(empty.contains("no secret"));

        let invalid = BwError::InvalidReference {
            reference: REF.to_string(),
        }
        .message();
        assert!(invalid.contains("bw://<item-uuid>/<field>"));

        let unsupported = BwError::UnsupportedField {
            reference: REF.to_string(),
            field: "totp".to_string(),
        }
        .message();
        assert!(unsupported.contains("totp"));
    }
}
