//! Tier-1 spec-case model and loader.

use serde_json::Value;
use std::path::{Path, PathBuf};

/// File encoding for the fixture writer. The corpus is utf8 except the two 9xx cases,
/// which need this knob.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Encoding {
  #[default]
  Utf8,
  /// One byte per `U+0000..=U+00FF` scalar. Latin1 is never detected; case 901 is
  /// ASCII-only so the utf8 read is byte-identical.
  Latin1,
  /// UTF-16LE with a leading `FF FE` BOM (case 902).
  Utf16Le,
}

/// One tier-1 spec case from `conformance/cases/spec/spec.json`.
#[derive(Clone, Debug)]
pub struct SpecCase {
  /// Spec case ID (`1xx` basic … `9xx` encodings).
  pub id: String,
  /// `.env` file content; materialized via [`crate::write_env_fixture`] honoring
  /// [`Self::encoding`].
  pub input: String,
  /// The effective parsed map as insertion-ordered entries. Key order is contract.
  pub expected: Vec<(String, String)>,
  /// Process-env preconditions merged over the standard base env. Only
  /// `{MACHINE: machine}` appears, on 11 cases.
  pub env: Vec<(String, String)>,
  /// File encoding (defaults to utf8; only cases 901/902 set it).
  pub encoding: Encoding,
  /// Provenance/semantics cross-references (informational).
  pub notes: Option<String>,
}

/// Absolute path to the tier-1 corpus, resolved from this crate's manifest dir.
pub fn spec_cases_path() -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR")).join("../cases/spec/spec.json")
}

/// Load and strictly validate the tier-1 corpus. Unknown fields, non-string values,
/// or unsupported encodings are hard errors: any surprise means the contract drifted.
pub fn load_spec_cases(path: &Path) -> Result<Vec<SpecCase>, String> {
  let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
  let root: Value =
    serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
  let arr = root
    .as_array()
    .ok_or_else(|| format!("{}: top level must be a JSON array", path.display()))?;
  arr.iter().map(parse_case).collect()
}

fn parse_case(value: &Value) -> Result<SpecCase, String> {
  let obj = value
    .as_object()
    .ok_or_else(|| format!("case must be a JSON object, got: {value}"))?;
  let id = string_field(obj, "id", "<missing id>")?;
  for key in obj.keys() {
    if !matches!(
      key.as_str(),
      "id" | "input" | "expected" | "env" | "encoding" | "notes"
    ) {
      return Err(format!(
                "{id}: unknown field {key:?}; the spec schema allows only id, input, expected, env, encoding, notes"
            ));
    }
  }
  let input = string_field(obj, "input", &id)?;
  let expected = entries_field(obj, "expected", &id)?
    .ok_or_else(|| format!("{id}: missing required field \"expected\""))?;
  let env = entries_field(obj, "env", &id)?.unwrap_or_default();
  let encoding = match obj.get("encoding") {
    None => Encoding::Utf8,
    Some(Value::String(s)) if s == "latin1" => Encoding::Latin1,
    Some(Value::String(s)) if s == "utf16le" => Encoding::Utf16Le,
    Some(other) => return Err(format!("{id}: unsupported encoding {other}")),
  };
  let notes = match obj.get("notes") {
    None => None,
    Some(Value::String(s)) => Some(s.clone()),
    Some(other) => return Err(format!("{id}: \"notes\" must be a string, got: {other}")),
  };
  Ok(SpecCase {
    id,
    input,
    expected,
    env,
    encoding,
    notes,
  })
}

fn string_field(
  obj: &serde_json::Map<String, Value>,
  field: &str,
  id: &str,
) -> Result<String, String> {
  match obj.get(field) {
    Some(Value::String(s)) => Ok(s.clone()),
    Some(other) => Err(format!("{id}: {field:?} must be a string, got: {other}")),
    None => Err(format!("{id}: missing required field {field:?}")),
  }
}

/// An object field as insertion-ordered `(key, value)` entries. Relies on
/// serde_json's `preserve_order` feature: object iteration follows the file's key
/// order, which the spec treats as contract.
fn entries_field(
  obj: &serde_json::Map<String, Value>,
  field: &str,
  id: &str,
) -> Result<Option<Vec<(String, String)>>, String> {
  let Some(value) = obj.get(field) else {
    return Ok(None);
  };
  let map = value
    .as_object()
    .ok_or_else(|| format!("{id}: {field:?} must be an object, got: {value}"))?;
  let mut entries = Vec::with_capacity(map.len());
  for (k, v) in map {
    match v {
      Value::String(s) => entries.push((k.clone(), s.clone())),
      other => {
        return Err(format!(
          "{id}: {field:?}[{k:?}] must be a string, got: {other}"
        ))
      }
    }
  }
  Ok(Some(entries))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn case_from(json: &str) -> Result<SpecCase, String> {
    parse_case(&serde_json::from_str(json).unwrap())
  }

  #[test]
  fn parses_minimal_case_with_defaults() {
    let c = case_from(r#"{"id":"101_BASIC","input":"BASIC=basic","expected":{"BASIC":"basic"}}"#)
      .unwrap();
    assert_eq!(c.id, "101_BASIC");
    assert_eq!(c.input, "BASIC=basic");
    assert_eq!(c.expected, vec![("BASIC".into(), "basic".into())]);
    assert!(c.env.is_empty());
    assert_eq!(c.encoding, Encoding::Utf8);
    assert!(c.notes.is_none());
  }

  #[test]
  fn expected_preserves_insertion_order() {
    // preserve_order is load-bearing: without it {"Z","A"} would sort.
    let c = case_from(r#"{"id":"X","input":"","expected":{"Z":"1","A":"2","M":"3"}}"#).unwrap();
    let keys: Vec<&str> = c.expected.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, ["Z", "A", "M"]);
  }

  #[test]
  fn unknown_field_is_rejected() {
    let err = case_from(r#"{"id":"X","input":"","expected":{},"bogus":true}"#).unwrap_err();
    assert!(err.contains("unknown field"), "{err}");
  }

  #[test]
  fn unsupported_encoding_is_rejected() {
    let err = case_from(r#"{"id":"X","input":"","expected":{},"encoding":"utf32"}"#).unwrap_err();
    assert!(err.contains("unsupported encoding"), "{err}");
  }

  #[test]
  fn non_string_expected_value_is_rejected() {
    let err = case_from(r#"{"id":"X","input":"","expected":{"A":1}}"#).unwrap_err();
    assert!(err.contains("must be a string"), "{err}");
  }
}
