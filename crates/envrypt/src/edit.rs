//! Key-name filtering used while loading a `.env` file, plus the in-place
//! `.env` value [`upsert`].

pub mod json_to_env;
pub(crate) mod key_glob;

pub use key_glob::{matcher, MatchError, Matcher};

use std::borrow::Cow;
use std::ops::Range;

use crate::parse::scan::LINE;

/// The include/exclude matcher pair shared by `scan` and `parse`.
/// Excludes win over includes. Patterns are deliberately limited to literal
/// names and `*`; see [`key_glob`] for the accepted grammar.
#[derive(Debug)]
pub struct KeyFilter {
  include: Matcher,
  exclude: Matcher,
  has_includes: bool,
}

impl KeyFilter {
  /// Builds a filter from include and exclude key patterns.
  pub fn new(includes: &[String], excludes: &[String]) -> Result<Self, MatchError> {
    Ok(Self {
      include: matcher(includes)?,
      exclude: matcher(excludes)?,
      has_includes: !includes.is_empty(),
    })
  }

  /// Returns whether a key should be omitted from parsing.
  pub fn skips(&self, name: &str) -> bool {
    self.exclude.is_match(name) || (self.has_includes && !self.include.is_match(name))
  }
}

/// The internal rewrite sentinel `\0ENVRYPT_UPSERT_<index>\0`. It is spliced into
/// the target value region so [`upsert`] can swap the real value in without a
/// naive `key=old` string replace hitting an identical earlier line. The NUL
/// framing keeps it out of any well-formed `.env` value; a src that embeds it
/// literally collides (pinned by `tests::upsert_placeholder_collision_*`).
const PLACEHOLDER_PREFIX: &str = "\0ENVRYPT_UPSERT_";
const PLACEHOLDER_SUFFIX: &str = "\0";

/// The value to write for a key in [`upsert`]. Only [`Single`](UpsertValue::Single)
/// is defined today: a single plain value written unquoted.
#[derive(Clone, Copy, Debug)]
pub enum UpsertValue<'a> {
  /// One value, written verbatim and unquoted. The caller keeps it to a clean
  /// charset (`[A-Za-z0-9_.:/@+-]`) so `scan` reads it back unchanged; a value
  /// carrying whitespace, quotes, `#`, `$`, or `=` is not round-trip safe.
  Single(&'a str),
}

/// Sets `key` to `value` in `src`, returning the rewritten text.
///
/// If `key` already occurs (per [`scan`](crate::parse::scan) with raw options),
/// the LAST occurrence's value is rewritten in place — every other line, comment,
/// and blank stays byte-for-byte. If `key` is absent, a `key=value` line is
/// appended (with a leading newline when `src` does not already end in one).
///
/// The function is pure and deterministic (no RNG, no global state) and never
/// panics on any input: a backtracking-engine error while locating occurrences
/// degrades to "no occurrence found", i.e. an append, never a panic.
pub fn upsert<'a>(src: &'a str, key: &str, value: UpsertValue<'_>) -> Cow<'a, str> {
  let UpsertValue::Single(formatted) = value;
  match last_value_span(src, key) {
    Some(span) => {
      // Splice the sentinel into the target region, then swap it for the real
      // value. `replacen(_, _, 1)` targets the first sentinel: normally the one
      // just inserted, but an earlier literal sentinel in `src` wins instead —
      // the documented, non-idempotent collision.
      let placeholder = placeholder(0);
      let mut marked = String::with_capacity(src.len() + placeholder.len());
      marked.push_str(&src[..span.start]);
      marked.push_str(&placeholder);
      marked.push_str(&src[span.end..]);
      Cow::Owned(marked.replacen(&placeholder, formatted, 1))
    }
    None => {
      let mut out = String::with_capacity(src.len() + key.len() + formatted.len() + 2);
      out.push_str(src);
      if !src.is_empty() && !src.ends_with('\n') {
        out.push('\n');
      }
      out.push_str(key);
      out.push('=');
      out.push_str(formatted);
      Cow::Owned(out)
    }
  }
}

/// The sentinel string for `index`, e.g. `\0ENVRYPT_UPSERT_0\0`.
fn placeholder(index: usize) -> String {
  format!("{PLACEHOLDER_PREFIX}{index}{PLACEHOLDER_SUFFIX}")
}

/// The byte range of the LAST occurrence of `key`'s raw value in `src`, using the
/// same tokenizer `scan` does so presence agrees with a raw scan. When the value
/// capture is absent (`K=`, `K=# c`), the range is the empty insertion point right
/// after the separator (see [`value_insert_index`]). Returns `None` when `key`
/// never occurs.
fn last_value_span(src: &str, key: &str) -> Option<Range<usize>> {
  let mut last = None;
  for caps in LINE.captures_iter(src) {
    // The tokenizer stops on an adversarial backtracking blowup rather than
    // panic, exactly as `scan` does; a truncated scan just yields no (further)
    // occurrence.
    let Ok(caps) = caps else { break };
    let Some(name) = caps.get(1) else { continue };
    if name.as_str() != key {
      continue;
    }
    last = Some(match caps.get(2) {
      Some(m) => m.range(),
      None => {
        let at = value_insert_index(src, name.end());
        at..at
      }
    });
  }
  last
}

/// The byte index where an empty occurrence's value belongs: right after the
/// `=` (or the `:`) separator that follows the key end at `name_end`. The match's
/// own end is unusable here — the tokenizer's greedy trailing whitespace can span
/// the closing newline (`K=\n` at end of text), which would push the insertion
/// onto a fresh dangling line.
fn value_insert_index(src: &str, name_end: usize) -> usize {
  let mut chars = src[name_end..].char_indices().peekable();
  // The `=` form allows leading whitespace (`K =`); the `:` form does not.
  while let Some(&(_, c)) = chars.peek() {
    if crate::parse::scan::is_js_whitespace(c) {
      chars.next();
    } else {
      break;
    }
  }
  match chars.next() {
    Some((offset, '=')) => name_end + offset + '='.len_utf8(),
    Some((offset, ':')) => name_end + offset + ':'.len_utf8(),
    // Only reached on a degenerate match with no separator; insert at the key
    // end rather than panic.
    _ => name_end,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use crate::parse::{scan, ScanOptions};

  /// The raw scan options `upsert` aligns with (doc 02 §9.1): no newline
  /// conversion, no double-quote escape expansion.
  fn raw_scan_options() -> ScanOptions {
    ScanOptions {
      convert_windows_newlines: false,
      expand_double_quoted_newlines: false,
      ..Default::default()
    }
  }

  fn scan_key_last(src: &str, key: &str) -> Option<String> {
    scan(src, &raw_scan_options())
      .get(key)
      .and_then(|occurrences| occurrences.last())
      .cloned()
  }

  fn upsert_owned(src: &str, key: &str, value: &str) -> String {
    upsert(src, key, UpsertValue::Single(value)).into_owned()
  }

  #[test]
  fn upsert_updates_last_occurrence_in_place() {
    let src = "A=1\nK=old\nB=2";
    let out = upsert_owned(src, "K", "new");
    assert_eq!(out, "A=1\nK=new\nB=2");
    assert_eq!(scan_key_last(&out, "K").as_deref(), Some("new"));
  }

  #[test]
  fn upsert_rewrites_the_last_of_duplicate_keys() {
    let out = upsert_owned("K=a\nK=b", "K", "new");
    assert_eq!(out, "K=a\nK=new");
    assert_eq!(scan_key_last(&out, "K").as_deref(), Some("new"));
  }

  #[test]
  fn upsert_fills_an_empty_value() {
    let out = upsert_owned("K=", "K", "v");
    assert_eq!(out, "K=v");
    assert_eq!(scan_key_last(&out, "K").as_deref(), Some("v"));
  }

  #[test]
  fn upsert_empty_value_at_end_of_text_updates_in_place() {
    // FUZZ: upsert_roundtrip — an empty-value occurrence whose line ends the
    // text (`K=\n`) once appended a dangling line, because the tokenizer's
    // greedy trailing whitespace pulled the match end past the newline.
    for src in ["K=\n", "A=1\nK=\n", "K=\n\n", "K="] {
      let out = upsert_owned(src, "K", "v");
      assert_eq!(
        scan_key_last(&out, "K").as_deref(),
        Some("v"),
        "src={src:?}"
      );
    }
  }

  #[test]
  fn upsert_appends_when_key_absent() {
    assert_eq!(upsert_owned("A=1", "K", "new"), "A=1\nK=new");
    assert_eq!(upsert_owned("A=1\n", "K", "new"), "A=1\nK=new");
    assert_eq!(upsert_owned("", "K", "new"), "K=new");
  }

  #[test]
  fn upsert_is_deterministic() {
    let src = "A=1\nK=old\n# comment\nK=older\n";
    let once = upsert_owned(src, "K", "brand-new");
    let again = upsert_owned(src, "K", "brand-new");
    assert_eq!(once, again);
  }

  #[test]
  fn upsert_clean_src_scans_back_to_value_and_is_scan_idempotent() {
    let src = "A=1\n\nK=old\nB=2";
    let value = "https://host:8080/p+a.b";
    let once = upsert_owned(src, "K", value);
    assert_eq!(scan_key_last(&once, "K").as_deref(), Some(value));
    let twice = upsert_owned(&once, "K", value);
    assert_eq!(scan_key_last(&twice, "K").as_deref(), Some(value));
  }

  #[test]
  fn upsert_placeholder_collision_swaps_an_earlier_literal() {
    // A src that embeds the rewrite sentinel defeats byte-idempotence: the
    // first-match swap lands on the embedded literal, not the inserted marker,
    // so pass 2 differs from pass 1.
    let ph = placeholder(0);
    let src = format!("J={ph}\nK=b");
    let once = upsert_owned(&src, "K", "new");
    assert_eq!(once, format!("J=new\nK={ph}"));
    let twice = upsert_owned(&once, "K", "new");
    assert_eq!(twice, "J=new\nK=new");
    assert_ne!(
      once, twice,
      "sentinel collision must be byte-non-idempotent"
    );
  }

  #[test]
  fn upsert_placeholder_collision_absent_stays_idempotent() {
    // Without the embedded sentinel the update is byte-idempotent.
    let once = upsert_owned("J=x\nK=b", "K", "new");
    assert_eq!(once, "J=x\nK=new");
    let twice = upsert_owned(&once, "K", "new");
    assert_eq!(once, twice);
  }
}
