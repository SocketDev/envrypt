//! Renders a JSON object as `.env` text.
//!
//! Each entry becomes one `KEY=value` line, in the object's insertion order
//! (`serde_json`'s `preserve_order`). A string value is written verbatim, or
//! double-quoted when it holds whitespace, a `#`, or a line break; a number or
//! boolean is stringified to its JSON scalar form (`42`, `true`); a `null`, an
//! array, or a nested object has no scalar `.env` form and is skipped. The
//! output ends with a trailing newline when it holds any line, and is `""` for
//! an empty object.

use serde_json::{Map, Value};

/// Renders `object` as `.env` text, one `KEY=value` line per entry in insertion
/// order. See the module docs for the per-value rules.
pub fn json_to_env(object: &Map<String, Value>) -> String {
  let mut out = String::new();
  for (key, value) in object {
    let rendered = match value {
      Value::String(text) => quote_if_needed(text),
      Value::Bool(_) | Value::Number(_) => value.to_string(),
      // Null and nested arrays/objects have no scalar `.env` form; skip them.
      _ => continue,
    };
    out.push_str(key);
    out.push('=');
    out.push_str(&rendered);
    out.push('\n');
  }
  out
}

/// Returns `value` verbatim, or double-quoted with control characters escaped
/// when it needs quoting to survive a round-trip through a `.env` reader.
fn quote_if_needed(value: &str) -> String {
  if !needs_quoting(value) {
    return value.to_string();
  }
  let escaped = value
    .replace('\\', "\\\\")
    .replace('"', "\\\"")
    .replace('\n', "\\n")
    .replace('\r', "\\r")
    .replace('\t', "\\t");
  format!("\"{escaped}\"")
}

/// True when `value` can't be written as a bare `.env` value: it holds
/// whitespace (which a reader would trim or split on) or a `#` (which would
/// start a trailing comment).
fn needs_quoting(value: &str) -> bool {
  value.chars().any(|c| c == '#' || c.is_whitespace())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn object(json: &str) -> Map<String, Value> {
    serde_json::from_str(json).unwrap()
  }

  #[test]
  fn writes_plain_key_value_lines_in_insertion_order() {
    let out = json_to_env(&object(r#"{"B":"2","A":"1"}"#));
    assert_eq!(out, "B=2\nA=1\n");
  }

  #[test]
  fn quotes_values_that_need_it() {
    let out = json_to_env(&object(r#"{"SPACE":"a b","HASH":"a#b","NL":"a\nb"}"#));
    assert_eq!(out, "SPACE=\"a b\"\nHASH=\"a#b\"\nNL=\"a\\nb\"\n");
  }

  #[test]
  fn empty_object_yields_empty_string() {
    assert_eq!(json_to_env(&object("{}")), "");
  }

  #[test]
  fn stringifies_scalars_and_skips_null_and_nested() {
    let out = json_to_env(&object(
      r#"{"N":42,"B":true,"NULL":null,"ARR":[1,2],"OBJ":{"k":"v"}}"#,
    ));
    assert_eq!(out, "N=42\nB=true\n");
  }
}
