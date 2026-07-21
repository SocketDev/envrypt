//! The full .env parse pipeline: scan → process-env precedence → decrypt (ring)
//! → evaluate (command substitution) → expand (with `\$` unescape) →
//! parsed/injected/existed/errors bookkeeping.
//!
//! [`parse_with_ring`] is the core synchronous pipeline over a prebuilt keyring;
//! [`public_key_hexes`] seeds that ring and orders decrypt attempts.

pub mod evaluate;
pub mod expand;
pub mod scan;

pub use evaluate::{evaluate, EvaluateOptions};
pub use expand::{expand, ExpandOptions};
pub use scan::{scan, scan_with, Quote, ScanEntry, ScanOptions};

use indexmap::IndexMap;
use std::borrow::Cow;
use std::path::Path;

/// Unescapes `\$` to `$`. Parse applies this to the expand result so an escaped
/// dollar survives expansion as a literal `$`.
pub fn resolve_escape_sequences(value: &str) -> Cow<'_, str> {
  // Nothing to unescape without the two-byte `\$` sequence, so borrow the input.
  if memchr::memmem::find(value.as_bytes(), b"\\$").is_none() {
    return Cow::Borrowed(value);
  }
  Cow::Owned(value.replace("\\$", "$"))
}

/// Scans `src` and, for every public-key name (in first-appearance order), takes
/// that name's last value. Seeds the ring and orders decrypt attempts. Uses the
/// default `ENVRYPT_PUBLIC_KEY` naming; [`public_key_hexes_with`] takes an
/// explicit [`KeyNaming`].
pub fn public_key_hexes(src: &str) -> Vec<String> {
  public_key_hexes_with(src, crate::conventions::keynames::default_key_naming())
}

/// [`public_key_hexes`] under an explicit [`KeyNaming`] (the configurable
/// key-resolution path).
pub fn public_key_hexes_with(
  src: &str,
  naming: &crate::conventions::keynames::KeyNaming,
) -> Vec<String> {
  scan(src, &ScanOptions::default())
    .iter()
    .filter(|(name, _)| naming.is_public_key_name(name))
    .map(|(_, values)| values.last().cloned().unwrap_or_default())
    .collect()
}

/// Options for [`parse_with_ring`]. These are the parse-time knobs; the ring
/// itself is built before the call.
#[derive(Clone, Copy, Debug)]
pub struct ParseOptions<'a> {
  /// `overload` — parsed-so-far wins over processEnv.
  pub overload: bool,
  /// `array` — collect every occurrence per key instead of last-wins.
  pub array: bool,
  /// Include-key globs. These gate decryption only; the scan itself stays
  /// unfiltered.
  pub ik: &'a [String],
  /// Exclude-key globs. These gate decryption only.
  pub ek: &'a [String],
  /// The pre-existing process environment.
  pub process_env: &'a IndexMap<String, String>,
  /// The keyring: public-key hex → private-key hex (`""` marks an unfilled
  /// seed). Insertion order (seeds first, then discovery order) drives the
  /// try-every-other-key fallback in [`try_decrypt`].
  pub ring: &'a IndexMap<String, String>,
  /// Working directory for `$()` children. `None` inherits the process cwd.
  pub cwd: Option<&'a Path>,
  /// The key-identifier naming used to detect the in-file public-key header when
  /// seeding decrypt-attempt order (default `ENVRYPT_`).
  pub naming: &'a crate::conventions::keynames::KeyNaming,
}

impl<'a> ParseOptions<'a> {
  /// Defaults: no overload, no array, no filters, empty ring, inherited cwd,
  /// default `ENVRYPT_` naming.
  pub fn new(process_env: &'a IndexMap<String, String>) -> Self {
    ParseOptions {
      overload: false,
      array: false,
      ik: &[],
      ek: &[],
      process_env,
      ring: empty_ring(),
      cwd: None,
      naming: crate::conventions::keynames::default_key_naming(),
    }
  }
}

/// A shared empty ring for the common unencrypted path.
pub fn empty_ring() -> &'static IndexMap<String, String> {
  static EMPTY: std::sync::LazyLock<IndexMap<String, String>> =
    std::sync::LazyLock::new(IndexMap::new);
  &EMPTY
}

/// The single aggregated parse error, produced only when a value fails to
/// decrypt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
  pub code: &'static str,
  pub message: String,
}

/// The parse result: `parsed`, `injected`, `existed`, and `errors`.
///
/// All maps are insertion-ordered; key order is part of the contract. Values are
/// `Vec<String>` to serve both modes: non-array mode keeps one element per key (a
/// later duplicate overwrites it in place), array mode pushes every occurrence in
/// file order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParseOutput {
  pub parsed: IndexMap<String, Vec<String>>,
  pub injected: IndexMap<String, Vec<String>>,
  pub existed: IndexMap<String, Vec<String>>,
  pub errors: Vec<ParseError>,
}

impl ParseOutput {
  /// Flattens `parsed` to one value per key (last wins), in insertion order.
  /// This is the effective map the conformance corpus asserts.
  pub fn parsed_map(&self) -> IndexMap<String, String> {
    self
      .parsed
      .iter()
      .map(|(k, v)| (k.clone(), v.last().cloned().unwrap_or_default()))
      .collect()
  }
}

/// The core parse pipeline over a prebuilt ring.
pub fn parse_with_ring(src: &str, opts: &ParseOptions) -> ParseOutput {
  let public_keys = public_key_hexes_with(src, opts.naming);
  let process_env = opts.process_env;

  // Build the ik/ek matcher pair once per call. An invalid pattern panics here;
  // callers that accept user-supplied globs pre-validate via `edit::KeyFilter`.
  let key_filter = crate::edit::KeyFilter::new(opts.ik, opts.ek).unwrap_or_else(|e| panic!("{e}"));
  let ik_skips = |name: &str| -> bool { key_filter.skips(name) };

  let mut running_parsed: IndexMap<String, String> = IndexMap::new();
  let mut literals: IndexMap<String, String> = IndexMap::new();
  let mut parsed: IndexMap<String, Vec<String>> = IndexMap::new();
  let mut injected: IndexMap<String, Vec<String>> = IndexMap::new();
  let mut existed: IndexMap<String, Vec<String>> = IndexMap::new();
  // Failed-decryption set: unique names in first-failure order.
  let mut failed: Vec<String> = Vec::new();

  // Scan runs unfiltered; the ik/ek matchers gate decryption only.
  scan_with(src, &ScanOptions::default(), |entry| {
    let name = entry.name;
    let quote = entry.quote;
    let mut k = entry.value.to_string();
    let has_own = process_env.contains_key(name);

    // Step 2: process-env precedence (key present).
    if !opts.overload && has_own {
      k = process_env[name].clone();
    }

    // Step 3.
    let was_encrypted = crate::crypto::is_encrypted(&k);

    // Step 4: decrypt, gated by ik/ek (skip when the filters exclude the name).
    if !ik_skips(name) {
      k = try_decrypt(opts.ring, &k, &public_keys, name);
      if was_encrypted && crate::crypto::is_encrypted(&k) && !failed.iter().any(|f| f == name) {
        failed.push(name.to_string());
      }
    }

    // Step 5.
    let still_encrypted = crate::crypto::is_encrypted(&k);
    let mut evaled = false;

    // Step 6: command substitution. Failures are swallowed, leaving the literal.
    if !still_encrypted
      && quote != Quote::Single
      && (!has_own || process_env.get(name).map(String::as_str) == Some(k.as_str()))
    {
      let before = k.clone();
      if let Ok(evaluated) = evaluate(
        &k,
        &EvaluateOptions {
          process_env,
          running_parsed: &running_parsed,
          cwd: opts.cwd,
        },
      ) {
        k = evaluated;
      }
      if before != k {
        evaled = true;
      }
    }

    // Step 7: expansion. Its gate tests truthiness (`!processEnv[name] ||
    // overload`), where steps 2 and 6 test key presence.
    let truthy_process_env = process_env.get(name).is_some_and(|v| !v.is_empty());
    if !still_encrypted
      && !evaled
      && quote != Quote::Single
      && (!truthy_process_env || opts.overload)
    {
      let expanded = expand(
        &k,
        &ExpandOptions {
          overload: opts.overload,
          process_env,
          running_parsed: &running_parsed,
          literals: &literals,
        },
      );
      let resolved_owned = match resolve_escape_sequences(&expanded) {
        Cow::Borrowed(_) => None,
        Cow::Owned(resolved) => Some(resolved),
      };
      k = resolved_owned.unwrap_or(expanded);
    }

    // Step 8: record single-quoted literals; expand's literals-guard reads them.
    if quote == Quote::Single {
      literals.insert(name.to_string(), k.clone());
    }

    // Step 9: runningParsed feeds later expansions and evaluate's child env.
    running_parsed.insert(name.to_string(), k.clone());

    // Step 10: array mode pushes each occurrence; non-array overwrites in
    // place, keeping the key's original position.
    if opts.array {
      parsed.entry(name.to_string()).or_default().push(k.clone());
    } else {
      let slot = parsed.entry(name.to_string()).or_default();
      slot.clear();
      slot.push(k.clone());
    }

    // Step 11: injected/existed bookkeeping.
    if has_own && !opts.overload {
      let process_value = process_env[name].clone();
      if opts.array {
        existed
          .entry(name.to_string())
          .or_default()
          .push(process_value);
      } else {
        let slot = existed.entry(name.to_string()).or_default();
        slot.clear();
        slot.push(process_value);
      }
    } else if opts.array {
      injected
        .entry(name.to_string())
        .or_default()
        .push(k.clone());
    } else {
      // Inject the current parsed value.
      let slot = injected.entry(name.to_string()).or_default();
      slot.clear();
      slot.push(k.clone());
    }

    k
  });

  // Exactly one aggregated error when any key failed decryption.
  let mut errors = Vec::new();
  if !failed.is_empty() {
    errors.push(ParseError {
      code: "DECRYPTION_FAILED",
      message: format!(
        "[DECRYPTION_FAILED] could not decrypt {}",
        failed.join(", ")
      ),
    });
  }

  ParseOutput {
    parsed,
    injected,
    existed,
    errors,
  }
}

/// Tries every candidate private key against `value` and returns the first
/// success, or `value` unchanged when all fail. Order: the keys named by
/// `public_key_hexes` first, then every other non-empty ring key in insertion
/// order. Each attempt routes on the payload version byte
/// (`crypto_v3::decrypt_entry`): a `0x03` payload takes the v3 path bound to
/// `name`; everything else takes the v1 path, which ignores the name and returns
/// non-`encrypted:` values untouched (so a plain value "succeeds" on the first
/// available key).
fn try_decrypt(
  ring: &IndexMap<String, String>,
  value: &str,
  public_key_hexes: &[String],
  name: &str,
) -> String {
  let mut tried: Vec<&str> = Vec::new();
  for public_key in public_key_hexes {
    let Some(private_key) = ring.get(public_key) else {
      continue;
    };
    if private_key.is_empty() {
      continue;
    }
    tried.push(private_key);
    if let Ok(decrypted) = crate::crypto_v3::decrypt_entry(private_key, value, name) {
      return decrypted;
    }
  }
  for private_key in ring.values() {
    if private_key.is_empty() || tried.iter().any(|t| t == private_key) {
      continue;
    }
    if let Ok(decrypted) = crate::crypto_v3::decrypt_entry(private_key, value, name) {
      return decrypted;
    }
  }
  value.to_string()
}

#[cfg(test)]
mod test_helpers {
  use super::*;

  pub(super) fn env(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    pairs
      .iter()
      .map(|(k, v)| (k.to_string(), v.to_string()))
      .collect()
  }

  pub(super) fn parse_env(src: &str, process_env: &IndexMap<String, String>) -> ParseOutput {
    parse_with_ring(src, &ParseOptions::new(process_env))
  }

  pub(super) fn value<'a>(out: &'a ParseOutput, key: &str) -> &'a str {
    out
      .parsed
      .get(key)
      .unwrap_or_else(|| panic!("key {key:?} missing from parsed"))
      .last()
      .unwrap()
  }

  pub(super) fn fixture_src(rel: &str) -> String {
    let path = test_support::fixture_path(rel);
    std::fs::read_to_string(&path)
      .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
  }
}

#[cfg(test)]
mod parse_test {
  // Pins the full parse pipeline against the root .env fixture
  // (conformance/fixtures/root/.env). None of the fixture keys are in the
  // process env, so parse runs with an empty process-env map.
  use super::test_helpers::*;
  use super::*;

  fn parsed() -> ParseOutput {
    parse_env(&fixture_src("root/.env"), &env(&[]))
  }

  #[test]
  fn parses_the_env_fixture_contract() {
    let out = parsed();
    assert_eq!(value(&out, "BASIC"), "basic");
    assert_eq!(value(&out, "AFTER_LINE"), "after_line");
    assert_eq!(value(&out, "EMPTY"), "");
    assert_eq!(value(&out, "EMPTY_SINGLE_QUOTES"), "");
    assert_eq!(value(&out, "EMPTY_DOUBLE_QUOTES"), "");
    assert_eq!(value(&out, "EMPTY_BACKTICKS"), "");
    assert_eq!(value(&out, "SINGLE_QUOTES"), "single_quotes");
    assert_eq!(value(&out, "SINGLE_QUOTES_SPACED"), "    single quotes    ");
    assert_eq!(value(&out, "DOUBLE_QUOTES"), "double_quotes");
    assert_eq!(value(&out, "DOUBLE_QUOTES_SPACED"), "    double quotes    ");
    assert_eq!(
      value(&out, "DOUBLE_QUOTES_INSIDE_SINGLE"),
      "double \"quotes\" work inside single quotes"
    );
    // $MONGOLAB_PORT is unset, so it expands to empty.
    assert_eq!(
      value(&out, "DOUBLE_QUOTES_WITH_NO_SPACE_BRACKET"),
      "{ port: }"
    );
    assert_eq!(
      value(&out, "SINGLE_QUOTES_INSIDE_DOUBLE"),
      "single 'quotes' work inside double quotes"
    );
    assert_eq!(
      value(&out, "BACKTICKS_INSIDE_SINGLE"),
      "`backticks` work inside single quotes"
    );
    assert_eq!(
      value(&out, "BACKTICKS_INSIDE_DOUBLE"),
      "`backticks` work inside double quotes"
    );
    assert_eq!(value(&out, "BACKTICKS"), "backticks");
    assert_eq!(value(&out, "BACKTICKS_SPACED"), "    backticks    ");
    assert_eq!(
      value(&out, "DOUBLE_QUOTES_INSIDE_BACKTICKS"),
      "double \"quotes\" work inside backticks"
    );
    assert_eq!(
      value(&out, "SINGLE_QUOTES_INSIDE_BACKTICKS"),
      "single 'quotes' work inside backticks"
    );
    assert_eq!(
      value(&out, "DOUBLE_AND_SINGLE_QUOTES_INSIDE_BACKTICKS"),
      "double \"quotes\" and single 'quotes' work inside backticks"
    );
    // Double quotes expand \n escapes; unquoted and single-quoted keep them
    // literal.
    assert_eq!(value(&out, "EXPAND_NEWLINES"), "expand\nnew\nlines");
    assert_eq!(value(&out, "DONT_EXPAND_UNQUOTED"), "dontexpand\\nnewlines");
    assert_eq!(value(&out, "DONT_EXPAND_SQUOTED"), "dontexpand\\nnewlines");
    assert!(!out.parsed.contains_key("COMMENTS"));
    assert_eq!(value(&out, "INLINE_COMMENTS"), "inline comments");
    assert_eq!(
      value(&out, "INLINE_COMMENTS_SINGLE_QUOTES"),
      "inline comments outside of #singlequotes"
    );
    assert_eq!(
      value(&out, "INLINE_COMMENTS_DOUBLE_QUOTES"),
      "inline comments outside of #doublequotes"
    );
    assert_eq!(
      value(&out, "INLINE_COMMENTS_BACKTICKS"),
      "inline comments outside of #backticks"
    );
    assert_eq!(
      value(&out, "INLINE_COMMENTS_SPACE"),
      "inline comments start with a"
    );
    assert_eq!(value(&out, "EQUAL_SIGNS"), "equals==");
    assert_eq!(value(&out, "RETAIN_INNER_QUOTES"), "{\"foo\": \"bar\"}");
    assert_eq!(
      value(&out, "RETAIN_INNER_QUOTES_AS_STRING"),
      "{\"foo\": \"bar\"}"
    );
    assert_eq!(
      value(&out, "RETAIN_INNER_QUOTES_AS_BACKTICKS"),
      "{\"foo\": \"bar's\"}"
    );
    assert_eq!(
      value(&out, "TRIM_SPACE_FROM_UNQUOTED"),
      "some spaced out string"
    );
    assert_eq!(value(&out, "USERNAME"), "therealnerdybeast@example.tld");
    assert_eq!(value(&out, "SPACED_KEY"), "parsed");
  }

  #[test]
  fn parses_a_buffer_into_an_object() {
    let out = parse_env("BUFFER=true", &env(&[]));
    assert_eq!(value(&out, "BUFFER"), "true");
  }

  #[test]
  fn parses_all_line_ending_styles() {
    // Every line-ending style parses identically.
    for src in [
      "SERVER=localhost\rPASSWORD=password\rDB=tests\r",
      "SERVER=localhost\nPASSWORD=password\nDB=tests\n",
      "SERVER=localhost\r\nPASSWORD=password\r\nDB=tests\r\n",
    ] {
      let out = parse_env(src, &env(&[]));
      let entries: Vec<(String, String)> = out.parsed_map().into_iter().collect();
      assert_eq!(
        entries,
        [
          ("SERVER".to_string(), "localhost".to_string()),
          ("PASSWORD".to_string(), "password".to_string()),
          ("DB".to_string(), "tests".to_string()),
        ],
        "line-ending style {src:?}"
      );
    }
  }
}

#[cfg(test)]
mod parse_multiline_test {
  // Pins multiline and split key/value parsing against
  // conformance/fixtures/root/.env.multiline.
  use super::test_helpers::*;

  const EXPECTED_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnNl1tL3QjKp3DZWM0T3u\nLgGJQwu9WqyzHKZ6WIA5T+7zPjO1L8l3S8k8YzBrfH4mqWOD1GBI8Yjq2L1ac3Y/\nbTdfHN8CmQr2iDJC0C6zY8YV93oZB3x0zC/LPbRYpF8f6OqX1lZj5vo2zJZy4fI/\nkKcI5jHYc8VJq+KCuRZrvn+3V+KuL9tF9v8ZgjF2PZbU+LsCy5Yqg1M8f5Jp5f6V\nu4QuUoobAgMBAAE=\n-----END PUBLIC KEY-----";

  #[test]
  fn parses_multiline_values_and_split_key_value_lines() {
    let out = parse_env(&fixture_src("root/.env.multiline"), &env(&[]));
    assert_eq!(
      value(&out, "MULTI_DOUBLE_QUOTED"),
      "THIS\nIS\nA\nMULTILINE\nSTRING"
    );
    assert_eq!(
      value(&out, "MULTI_SINGLE_QUOTED"),
      "THIS\nIS\nA\nMULTILINE\nSTRING"
    );
    assert_eq!(
      value(&out, "MULTI_BACKTICKED"),
      "THIS\nIS\nA\n\"MULTILINE'S\"\nSTRING"
    );
    // Exact multiline PEM block.
    assert_eq!(value(&out, "MULTI_PEM_DOUBLE_QUOTED"), EXPECTED_PEM);
    // Split key/value lines.
    assert_eq!(value(&out, "SPLIT_KEY_VALUE_LINES"), "split line");
    assert_eq!(
      value(&out, "SPLIT_KEY_VALUE_SPACED_LINES"),
      "split line with spaces"
    );
  }
}

#[cfg(test)]
mod config_expand_test {
  // Pins variable expansion against conformance/fixtures/root/.env.expand. The
  // pipeline runs with an injected process-env map; nothing mutates the real
  // environment.
  use super::test_helpers::*;
  use super::*;

  fn expand_fixture(process_env: &IndexMap<String, String>, overload: bool) -> ParseOutput {
    let src = fixture_src("root/.env.expand");
    let mut opts = ParseOptions::new(process_env);
    opts.overload = overload;
    parse_with_ring(&src, &opts)
  }

  #[test]
  fn expands() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "BASIC"), "basic");
    assert_eq!(value(&out, "BASIC_EXPAND"), "basic");
    assert_eq!(value(&out, "MACHINE_EXPAND"), "file");
  }

  #[test]
  fn expands_using_the_machine_value_first_if_it_exists() {
    let out = expand_fixture(&env(&[("MACHINE", "machine")]), false);
    assert_eq!(value(&out, "MACHINE"), "machine");
    assert_eq!(value(&out, "MACHINE_EXPAND"), "machine");
  }

  #[test]
  fn expands_to_bring_own_process_env() {
    // The injected map is caller-owned, so this asserts the parsed values.
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "BASIC"), "basic");
    assert_eq!(value(&out, "BASIC_EXPAND"), "basic");
    assert_eq!(value(&out, "MACHINE_EXPAND"), "file");
    assert_eq!(out.injected.get("BASIC").unwrap().last().unwrap(), "basic");
    assert!(out.existed.is_empty());
  }

  #[test]
  fn expands_env_expand_correctly() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "ESCAPED_EXPAND"), "$ESCAPED");
    assert_eq!(value(&out, "EXPAND_DEFAULT"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED2"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED_TWICE"), "filedefault");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED_TWICE2"), "filedefault");
    assert_eq!(value(&out, "EXPAND_DEFAULT_SPECIAL_CHARACTERS"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_SPECIAL_CHARACTERS2"), "file");
    assert_eq!(value(&out, "UNDEFINED_EXPAND"), "");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_NESTED"), "file");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT"), "default");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT2"), "default");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED"), "default");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED2"), "default");
    assert_eq!(
      value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED_TWICE"),
      "default"
    );
    assert_eq!(
      value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED_TWICE2"),
      "default"
    );
    assert_eq!(
      value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS"),
      "/default/path:with/colon"
    );
    assert_eq!(
      value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS2"),
      "/default/path:with/colon"
    );
    assert_eq!(
      value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS_NESTED"),
      "/default/path:with/colon"
    );
    assert_eq!(
      value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS_NESTED2"),
      "/default/path:with/colon"
    );
    assert_eq!(
      value(
        &out,
        "NO_CURLY_BRACES_UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS"
      ),
      ":-/default/path:with/colon"
    );
    assert_eq!(
      value(
        &out,
        "NO_CURLY_BRACES_UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS2"
      ),
      "-/default/path:with/colon"
    );
  }

  #[test]
  fn expands_env_expand_correctly_when_machine_already_set() {
    let out = expand_fixture(&env(&[("MACHINE", "machine")]), false);
    assert_eq!(value(&out, "ESCAPED_EXPAND"), "$ESCAPED");
    assert_eq!(value(&out, "EXPAND_DEFAULT"), "machine");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED"), "machine");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED2"), "machine");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED_TWICE"), "machinedefault");
    assert_eq!(
      value(&out, "EXPAND_DEFAULT_NESTED_TWICE2"),
      "machinedefault"
    );
    assert_eq!(value(&out, "EXPAND_DEFAULT_SPECIAL_CHARACTERS"), "machine");
    assert_eq!(value(&out, "EXPAND_DEFAULT_SPECIAL_CHARACTERS2"), "machine");
    assert_eq!(value(&out, "UNDEFINED_EXPAND"), "");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_NESTED"), "machine");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT"), "default");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT2"), "default");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED"), "default");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED2"), "default");
    assert_eq!(
      value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED_TWICE"),
      "default"
    );
    assert_eq!(
      value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED_TWICE2"),
      "default"
    );
    assert_eq!(
      value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS"),
      "/default/path:with/colon"
    );
    assert_eq!(
      value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS2"),
      "/default/path:with/colon"
    );
    assert_eq!(
      value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS_NESTED"),
      "/default/path:with/colon"
    );
    assert_eq!(
      value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS_NESTED2"),
      "/default/path:with/colon"
    );
  }

  #[test]
  fn expands_correctly_when_machine_set_but_overload_true() {
    let out = expand_fixture(&env(&[("MACHINE", "machine")]), true);
    assert_eq!(value(&out, "MACHINE"), "file");
    assert_eq!(value(&out, "MACHINE_EXPAND"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED2"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED_TWICE"), "filedefault");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED_TWICE2"), "filedefault");
    assert_eq!(value(&out, "EXPAND_DEFAULT_SPECIAL_CHARACTERS"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_SPECIAL_CHARACTERS2"), "file");
    assert_eq!(value(&out, "UNDEFINED_EXPAND"), "");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_NESTED"), "file");
  }

  #[test]
  fn expands_mongo_real_world_example() {
    let out = expand_fixture(&env(&[]), false);
    let uri = "mongodb://username:password@abcd1234.mongolab.com:12345/heroku_db";
    assert_eq!(value(&out, "MONGOLAB_URI"), uri);
    assert_eq!(value(&out, "MONGOLAB_URI_RECURSIVELY"), uri);
    assert_eq!(value(&out, "NO_CURLY_BRACES_URI"), uri);
    assert_eq!(value(&out, "NO_CURLY_BRACES_URI_RECURSIVELY"), uri);
  }

  #[test]
  fn expands_with_periods_in_key_name() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "POSTGRESQL.MAIN.USER"), "postgres");
  }

  #[test]
  fn does_not_expand_dollar() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "DOLLAR"), "$");
  }

  #[test]
  fn handles_one_two() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "ONETWO"), "onetwo");
    assert_eq!(value(&out, "ONETWO_SIMPLE"), "onetwo");
    assert_eq!(value(&out, "ONETWO_SIMPLE2"), "onetwo");
    assert_eq!(value(&out, "ONETWO_SUPER_SIMPLE"), "onetwo");
  }

  #[test]
  fn handles_two_dollar_signs() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(
      value(&out, "TWO_DOLLAR_SIGNS_FOLLOWED_BY_DIGIT"),
      "abcd$$1234foo"
    );
    assert_eq!(value(&out, "TWO_DOLLAR_SIGNS_FOLLOWED_BY_LETTER"), "pa$@");
    assert_eq!(
      value(&out, "TWO_DOLLAR_SIGNS_FOLLOWED_BY_LETTER_SINGLE_QUOTE"),
      "pa$$word@"
    );
  }

  #[test]
  fn does_not_choke() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(
      value(&out, "DONT_CHOKE1"),
      ".kZh`>4[,[DDU-*Jt+[;8-,@K=,9%;F9KsoXqOE)gpG^X!{)Q+/9Fc(QF}i[NEi!"
    );
    assert_eq!(
      value(&out, "DONT_CHOKE2"),
      r"=;+=CNy3)-D=zI6gRP2w\$B@0K;Y]e^EFnCmx\$Dx?;.9wf-rgk1BcTR0]JtY<S:b_"
    );
    assert_eq!(
      value(&out, "DONT_CHOKE3"),
      "MUcKSGSY@HCON<1S_siWTP`DgS*Ug],mu]SkqI|7V2eOk9:>&fw;>HEwms`D8E2H"
    );
    assert_eq!(
      value(&out, "DONT_CHOKE4"),
      "m]zjzfRItw2gs[2:{p{ugENyFw9m)tH6_VCQzer`*noVaI<vqa3?FZ9+6U;K#Bfd"
    );
    assert_eq!(
      value(&out, "DONT_CHOKE5"),
      "#la__nK?IxNlQ%`5q&DpcZ>Munx=[1-AMgAcwmPkToxTaB?kgdF5y`A8m=Oa-B!)"
    );
    assert_eq!(
      value(&out, "DONT_CHOKE6"),
      r"xlC&*<j4J<d._<JKH0RBJV!4(ZQEN-+&!0p137<g*hdY2H4xk?/;KO1\$(W{:Wc}Q"
    );
    assert_eq!(
      value(&out, "DONT_CHOKE7"),
      r"?\$6)m*xhTVewc#NVVgxX%eBhJjoHYzpXFg=gzn[rWXPLj5UWj@z\$/UDm8o79n/p%"
    );
    assert_eq!(
      value(&out, "DONT_CHOKE8"),
      "@}:[4#g%[R-CFR});bY(Z[KcDQDsVn2_y4cSdU<Mjy!c^F`G<!Ks7]kbS]N1:bP:"
    );
  }

  #[test]
  fn expands_domain_with_host() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "HOST"), "something");
    assert_eq!(value(&out, "DOMAIN"), "https://something");
  }

  #[test]
  fn does_not_expand_single_quote() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "SINGLE_QUOTE"), "$BASIC");
  }

  #[test]
  fn handles_deep_nesting() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(
      value(&out, "DEEP8"),
      "prefix5-prefix4-prefix3-prefix2-prefix1-basic-suffix1-suffix2-suffix3-suffix4-suffix5"
    );
  }

  #[test]
  fn handles_self_referencing() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "EXPAND_SELF"), "");
    assert_eq!(value(&out, "DEEP_SELF"), "basic-bar");
    assert_eq!(value(&out, "DEEP_SELF_PRIOR"), "prefix2-foo-suffix2");
  }

  #[test]
  fn handles_progressive_updating() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "PROGRESSIVE"), "first-second");
  }

  #[test]
  fn single_quote_expansion_bug_test_cases() {
    // Single-quote expansion regressions (issues #422/#674).
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "PGUSER"), "user");
    assert_eq!(value(&out, "PGHOST"), "localhost");
    assert_eq!(
      value(&out, "DATABASE_URL"),
      "postgres://user@localhost/my_database"
    );
    assert_eq!(value(&out, "PGUSER2"), "user");
    assert_eq!(value(&out, "PGHOST2"), "localhost");
    assert_eq!(
      value(&out, "DATABASE_URL2"),
      "postgres://user@localhost/my_database"
    );
    assert_eq!(value(&out, "PGUSER3"), "user");
    assert_eq!(value(&out, "PGHOST3"), "localhost");
    assert_eq!(
      value(&out, "DATABASE_URL3"),
      "postgres://user@localhost/my_database"
    );
    assert_eq!(value(&out, "PGUSER4"), "user");
    assert_eq!(value(&out, "PGHOST4"), "localhost");
    assert_eq!(
      value(&out, "DATABASE_URL4"),
      "postgres://user@localhost/my_database"
    );
    assert_eq!(value(&out, "PGUSER5"), "user");
    assert_eq!(value(&out, "PGHOST5"), "localhost");
    assert_eq!(
      value(&out, "DATABASE_URL5"),
      "postgres://user@localhost/my_database"
    );
  }
}

#[cfg(test)]
mod pipeline_tests {
  // Pins the per-entry transform order, the step gates, and the end-to-end
  // output shapes, including encrypted values.
  use super::test_helpers::*;
  use super::*;

  fn entries(map: &IndexMap<String, Vec<String>>) -> Vec<(String, Vec<String>)> {
    map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
  }

  fn one(pairs: &[(&str, &str)]) -> Vec<(String, Vec<String>)> {
    pairs
      .iter()
      .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
      .collect()
  }

  #[test]
  fn verified_end_to_end_shape_default() {
    let pe = env(&[("PRE", "exists")]);
    let out = parse_env("PRE=file\nNEW=fresh\nREF=${PRE}-x", &pe);
    assert_eq!(
      entries(&out.parsed),
      one(&[("PRE", "exists"), ("NEW", "fresh"), ("REF", "exists-x")])
    );
    assert_eq!(
      entries(&out.injected),
      one(&[("NEW", "fresh"), ("REF", "exists-x")])
    );
    assert_eq!(entries(&out.existed), one(&[("PRE", "exists")]));
    assert!(out.errors.is_empty());
  }

  #[test]
  fn verified_end_to_end_shape_overload() {
    let pe = env(&[("PRE", "exists")]);
    let mut opts = ParseOptions::new(&pe);
    opts.overload = true;
    let out = parse_with_ring("PRE=file\nREF=${PRE}-x", &opts);
    assert_eq!(
      entries(&out.parsed),
      one(&[("PRE", "file"), ("REF", "file-x")])
    );
    assert_eq!(
      entries(&out.injected),
      one(&[("PRE", "file"), ("REF", "file-x")])
    );
    assert!(out.existed.is_empty());
    assert!(out.errors.is_empty());
  }

  #[test]
  fn verified_end_to_end_shape_array() {
    let pe = env(&[]);
    let mut opts = ParseOptions::new(&pe);
    opts.array = true;
    let out = parse_with_ring("L=one\nL=two", &opts);
    assert_eq!(
      entries(&out.parsed),
      vec![("L".to_string(), vec!["one".to_string(), "two".to_string()])]
    );
    assert_eq!(
      entries(&out.injected),
      vec![("L".to_string(), vec!["one".to_string(), "two".to_string()])]
    );
    assert!(out.existed.is_empty());
  }

  #[test]
  fn duplicates_last_wins_keeps_original_position() {
    // A duplicate overwrites, keeping the key's original position.
    let out = parse_env("L=one\nMID=x\nL=two", &env(&[]));
    assert_eq!(entries(&out.parsed), one(&[("L", "two"), ("MID", "x")]));
  }

  #[cfg(unix)]
  mod command_substitution_gates {
    use super::*;

    #[test]
    fn fresh_value_is_evaluated() {
      let out = parse_env("CMD=$(echo hi)", &env(&[]));
      assert_eq!(value(&out, "CMD"), "hi");
    }

    #[test]
    fn preexisting_different_process_env_value_is_never_evaluated() {
      let out = parse_env("CMD=$(echo hi)", &env(&[("CMD", "other")]));
      assert_eq!(value(&out, "CMD"), "other");
      assert_eq!(out.existed.get("CMD").unwrap().last().unwrap(), "other");
    }

    #[test]
    fn preexisting_process_env_value_itself_is_evaluated() {
      // The process-env value is evaluated when it equals k (step 2 set
      // k = processEnv[name]).
      let out = parse_env("CMD=$(echo file)", &env(&[("CMD", "$(echo hi)")]));
      assert_eq!(value(&out, "CMD"), "hi");
      assert_eq!(
        out.existed.get("CMD").unwrap().last().unwrap(),
        "$(echo hi)"
      );
    }

    #[test]
    fn overload_with_preexisting_different_value_skips_eval_entirely() {
      // Quirk: the eval gate tests key-presence + equality. Overload keeps
      // the file value, which fails the equality arm, so the literal
      // survives (expand cannot touch `$(`).
      let pe = env(&[("CMD", "other")]);
      let mut opts = ParseOptions::new(&pe);
      opts.overload = true;
      let out = parse_with_ring("CMD=$(echo hi)", &opts);
      assert_eq!(value(&out, "CMD"), "$(echo hi)");
    }

    #[test]
    fn single_quoted_value_is_never_evaluated() {
      let out = parse_env("CMD='$(echo hi)'", &env(&[]));
      assert_eq!(value(&out, "CMD"), "$(echo hi)");
    }

    #[test]
    fn failing_command_is_swallowed_and_value_stays_literal() {
      // A failing command is swallowed; no parse error surfaces.
      let out = parse_env("CMD=$(exit 3)", &env(&[]));
      assert_eq!(value(&out, "CMD"), "$(exit 3)");
      assert!(out.errors.is_empty());
    }

    #[test]
    fn evaluated_values_feed_running_parsed_for_later_lines() {
      let out = parse_env("A=$(echo one)\nB=${A}-2\nC=$(echo $A)", &env(&[]));
      assert_eq!(value(&out, "A"), "one");
      assert_eq!(value(&out, "B"), "one-2");
      assert_eq!(value(&out, "C"), "one");
    }
  }

  #[test]
  fn escaped_dollar_is_unescaped_by_resolve_escape_sequences() {
    // The lookbehind blocks expansion of `\$ESCAPED`; resolveEscapeSequences
    // then unescapes it to `$ESCAPED`.
    let out = parse_env("E=\\$ESCAPED", &env(&[]));
    assert_eq!(value(&out, "E"), "$ESCAPED");
    // Single-quoted values reach neither expand nor resolveEscapeSequences.
    let out = parse_env("E='\\$KEEP'", &env(&[]));
    assert_eq!(value(&out, "E"), "\\$KEEP");
  }

  #[test]
  fn empty_string_preexisting_value_still_expands_and_is_existed() {
    // Step 7's gate tests truthiness (`!processEnv[name]`), where steps 2 and
    // 6 test key presence. An empty pre-existing value wins at step 2 and
    // still flows through expand.
    let out = parse_env("PRE=${BASIC}-x\nBASIC=basic", &env(&[("PRE", "")]));
    assert_eq!(value(&out, "PRE"), "");
    assert_eq!(out.existed.get("PRE").unwrap().last().unwrap(), "");
    assert_eq!(value(&out, "BASIC"), "basic");
  }

  #[test]
  fn resolve_escape_sequences_unit() {
    assert_eq!(resolve_escape_sequences(r"\$A and \$B"), "$A and $B");
    assert_eq!(resolve_escape_sequences("no dollars"), "no dollars");
  }

  #[test]
  fn public_key_hexes_last_value_per_key_in_first_appearance_order() {
    // Last value per public-key name, in first-appearance order.
    let src = "ENVRYPT_PUBLIC_KEY=a\nENVRYPT_PUBLIC_KEY_PRODUCTION=b\nENVRYPT_PUBLIC_KEY=c";
    assert_eq!(
      public_key_hexes(src),
      vec!["c".to_string(), "b".to_string()]
    );
    assert!(public_key_hexes("HELLO=world").is_empty());
  }

  mod encrypted_values {
    // Decrypt happens inside the pipeline, then the plaintext is reprocessed.
    use super::*;
    use crate::crypto;

    fn ring_of(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
      pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    #[test]
    #[cfg(unix)]
    fn decrypted_plaintext_is_reprocessed_through_evaluate_and_expand() {
      let kp = crypto::keypair();
      let secret = crypto::encrypt(&kp.public_key, "${BASE}-world", true).unwrap();
      let cmdsecret = crypto::encrypt(&kp.public_key, "$(echo dyn)", true).unwrap();
      let src = format!(
        "ENVRYPT_PUBLIC_KEY=\"{}\"\nBASE=hello\nSECRET=\"{}\"\nCMDSECRET=\"{}\"",
        kp.public_key, secret, cmdsecret
      );
      let pe = env(&[]);
      let ring = ring_of(&[(kp.public_key.as_str(), kp.private_key.as_str())]);
      let mut opts = ParseOptions::new(&pe);
      opts.ring = &ring;
      let out = parse_with_ring(&src, &opts);
      assert_eq!(value(&out, "SECRET"), "hello-world");
      assert_eq!(value(&out, "CMDSECRET"), "dyn");
      assert!(out.errors.is_empty());
    }

    #[test]
    fn failed_decryption_keeps_ciphertext_and_aggregates_one_error() {
      let kp = crypto::keypair();
      let secret = crypto::encrypt(&kp.public_key, "plain", true).unwrap();
      let cmdsecret = crypto::encrypt(&kp.public_key, "other", true).unwrap();
      let src = format!(
        "ENVRYPT_PUBLIC_KEY=\"{}\"\nBASE=hello\nSECRET=\"{}\"\nCMDSECRET=\"{}\"",
        kp.public_key, secret, cmdsecret
      );
      let pe = env(&[]);
      // Ring seeded but unfilled ("") — decryption cannot succeed.
      let ring = ring_of(&[(kp.public_key.as_str(), "")]);
      let mut opts = ParseOptions::new(&pe);
      opts.ring = &ring;
      let out = parse_with_ring(&src, &opts);
      assert_eq!(value(&out, "SECRET"), secret.as_str());
      assert_eq!(value(&out, "CMDSECRET"), cmdsecret.as_str());
      assert_eq!(
        out.errors,
        vec![ParseError {
          code: "DECRYPTION_FAILED",
          message: "[DECRYPTION_FAILED] could not decrypt SECRET, CMDSECRET".to_string(),
        }]
      );
    }

    #[test]
    fn ek_excluded_keys_skip_decryption_without_error() {
      // The ik/ek matchers gate decryption only; an excluded key keeps its
      // ciphertext and is not recorded as a failure.
      let kp = crypto::keypair();
      let secret = crypto::encrypt(&kp.public_key, "sekret", true).unwrap();
      let other = crypto::encrypt(&kp.public_key, "плейн", true).unwrap();
      let src = format!(
        "ENVRYPT_PUBLIC_KEY=\"{}\"\nSECRET=\"{}\"\nOTHER=\"{}\"",
        kp.public_key, secret, other
      );
      let pe = env(&[]);
      let ring = ring_of(&[(kp.public_key.as_str(), kp.private_key.as_str())]);
      let ek = vec!["SECRET".to_string()];
      let mut opts = ParseOptions::new(&pe);
      opts.ring = &ring;
      opts.ek = &ek;
      let out = parse_with_ring(&src, &opts);
      assert_eq!(value(&out, "SECRET"), secret.as_str());
      assert_eq!(value(&out, "OTHER"), "плейн");
      assert!(out.errors.is_empty());
    }

    #[test]
    fn ring_fallback_tries_every_other_key_after_the_seeded_ones() {
      // try_decrypt uses the public-key-named keys first, then every
      // remaining ring key.
      let kp1 = crypto::keypair();
      let kp2 = crypto::keypair();
      let secret = crypto::encrypt(&kp2.public_key, "via-kp2", true).unwrap();
      let src = format!(
        "ENVRYPT_PUBLIC_KEY=\"{}\"\nSECRET=\"{}\"",
        kp1.public_key, secret
      );
      let pe = env(&[]);
      let ring = ring_of(&[
        (kp1.public_key.as_str(), kp1.private_key.as_str()),
        (kp2.public_key.as_str(), kp2.private_key.as_str()),
      ]);
      let mut opts = ParseOptions::new(&pe);
      opts.ring = &ring;
      let out = parse_with_ring(&src, &opts);
      assert_eq!(value(&out, "SECRET"), "via-kp2");
      assert!(out.errors.is_empty());
    }

    #[test]
    fn still_encrypted_values_skip_evaluate_and_expand() {
      // While the `encrypted:` prefix remains, evaluate and expand are both
      // skipped.
      let src = "SECRET=\"encrypted:${NOT_EXPANDED}\"";
      let out = parse_env(src, &env(&[("NOT_EXPANDED", "boom")]));
      assert_eq!(value(&out, "SECRET"), "encrypted:${NOT_EXPANDED}");
      assert_eq!(
        out.errors[0].message,
        "[DECRYPTION_FAILED] could not decrypt SECRET"
      );
    }
  }

  #[test]
  fn utf16le_decoded_bom_is_absorbed_by_the_line_regex() {
    // A decoded U+FEFF at position 0 counts as whitespace to the line regex,
    // so the key still parses.
    let out = parse_env("\u{FEFF}HELLO=utf16le", &env(&[]));
    assert_eq!(value(&out, "HELLO"), "utf16le");
  }
}
