//! `expand()` — variable expansion.
//!
//! The expansion algorithm the code implements:
//! * the `(?<!\\)` lookbehind skips escaped `\$` (fancy-regex);
//! * the operators `-`/`+` test whether a name is set, while `:-`/`:+` test
//!   truthiness;
//! * first operator wins, then split on all its occurrences and rejoin the
//!   default;
//! * with no operator, `split(null)` splits on the literal string `"null"`;
//! * `String.replace(searchString, replacement)` replaces the first literal
//!   occurrence (which may sit before the regex match, e.g. an escaped `\$`), and
//!   the `$$`/`$&`/`` $` ``/`$'` substitution patterns are live in the
//!   replacement string;
//! * the scan restarts from index 0 after every replacement and breaks when the
//!   whole result equals `env[name]` or the literals guard trips.

use indexmap::IndexMap;
use std::sync::LazyLock;

/// The main expansion regex:
/// `/(?<!\)\${([^{}]+)}|(?<!\)\$([A-Za-z_][A-Za-z0-9_]*)/g`. The lookbehind needs
/// fancy-regex.
static EXPAND_RE: LazyLock<fancy_regex::Regex> = LazyLock::new(|| {
  fancy_regex::Regex::new(r"(?<!\\)\$\{([^{}]+)\}|(?<!\\)\$([A-Za-z_][A-Za-z0-9_]*)")
    .expect("EXPAND regex compiles")
});

/// Operator scan: `/(:\+|\+|:-|-)/`, first match anywhere.
static OP_RE: LazyLock<regex::Regex> =
  LazyLock::new(|| regex::Regex::new(r"(:\+|\+|:-|-)").expect("OP regex compiles"));

/// The literals-guard test regex (no lookbehind):
/// `/\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*/`.
static LITERAL_PATTERN_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
  regex::Regex::new(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*").expect("pattern-test regex compiles")
});

/// Options for [`expand`].
#[derive(Clone, Copy, Debug)]
pub struct ExpandOptions<'a> {
  /// Lookup order for names. By default processEnv wins over runningParsed;
  /// `overload` flips it.
  pub overload: bool,
  pub process_env: &'a IndexMap<String, String>,
  /// Keys parsed earlier in the same file (progressive expansion).
  pub running_parsed: &'a IndexMap<String, String>,
  /// Values defined single-quoted earlier in the file; the literals guard reads
  /// them.
  pub literals: &'a IndexMap<String, String>,
  /// The byte budget for the expanded value; exceeding it is
  /// [`ExpandError`]. Default [`DEFAULT_MAX_EXPAND_OUTPUT_BYTES`].
  pub max_output_bytes: usize,
}

/// [`expand`] refused to grow its result past
/// [`ExpandOptions::max_output_bytes`]. Carries the budget that was hit so the
/// caller can name it in the error it raises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpandError {
  /// The byte budget the expansion tried to exceed.
  pub max_output_bytes: usize,
}

/// Expands `${VAR}` and `$VAR` references in `value`.
///
/// A class of self-reinserting replacements (for example `$&` in an env value, or
/// `expand("X ${SET}")` with `SET='${SET}'`) never terminates. Two guards bound
/// it: the loop caps at [`MAX_EXPAND_ITERATIONS`] replacements, and the result
/// may not grow past [`ExpandOptions::max_output_bytes`]. Every terminating input
/// finishes far below both.
///
/// The additive members of that class (a replacement that reinserts the match
/// verbatim) hit the iteration cap and return the current result. The
/// multiplicative members (a `$'`/`` $` ``/`$&` replacement that duplicates a
/// still-`${…}`-bearing tail, doubling per pass) reach the byte budget in about
/// 20 passes from a KB-scale input, and return [`ExpandError`] rather than
/// growing until the host runs out of memory. The value is never silently
/// truncated: a caller that hits the budget gets an error, not a shortened
/// secret.
pub fn expand(value: &str, opts: &ExpandOptions) -> Result<String, ExpandError> {
  // EXPAND_RE cannot match without a `$` byte.
  if memchr::memchr(b'$', value.as_bytes()).is_none() {
    return Ok(value.to_string());
  }

  // Lookup order over the two maps: processEnv wins by default, runningParsed
  // under overload.
  let env_get = |name: &str| -> Option<&str> {
    let (winner, loser): (&IndexMap<String, String>, &IndexMap<String, String>) = if opts.overload {
      (opts.running_parsed, opts.process_env)
    } else {
      (opts.process_env, opts.running_parsed)
    };
    winner
      .get(name)
      .or_else(|| loser.get(name))
      .map(String::as_str)
  };
  let env_has = |name: &str| -> bool {
    opts.process_env.contains_key(name) || opts.running_parsed.contains_key(name)
  };

  let mut result = value.to_string();
  // One iteration is one replacement; the regex restarts from index 0 each
  // time. The cap bounds the non-terminating class (see the function docs).
  for _ in 0..MAX_EXPAND_ITERATIONS {
    // An engine error (backtracking limit) counts as no match. The pattern
    // has no nested quantifiers, so this is unreachable in practice.
    let Some(caps) = EXPAND_RE.captures(&result).ok().flatten() else {
      break;
    };
    let template = caps
      .get(0)
      .expect("group 0 always present")
      .as_str()
      .to_string();
    let expression = caps
      .get(1)
      .or_else(|| caps.get(2))
      .expect("one of the two alternatives captured")
      .as_str()
      .to_string();

    // First operator match anywhere, then split on all its occurrences and
    // rejoin the remainder. With no operator, `split(null)` splits on the
    // literal string "null".
    let splitter = OP_RE.find(&expression).map(|m| m.as_str().to_string());
    let sep: &str = splitter.as_deref().unwrap_or("null");
    let mut parts = expression.split(sep);
    let name = parts.next().unwrap_or("").to_string();
    let default_value = parts.collect::<Vec<_>>().join(sep);

    let is_set = env_has(&name);
    let env_value = env_get(&name);
    let truthy = env_value.is_some_and(|v| !v.is_empty());
    let replacement: String = match splitter.as_deref() {
      // `:-` truthy default, `-` set default, `:+` truthy alternate,
      // `+` set alternate, none: truthy value or "".
      Some(":-") => {
        if truthy {
          env_value.unwrap_or("").to_string()
        } else {
          default_value
        }
      }
      Some("-") => {
        if is_set {
          env_value.unwrap_or("").to_string()
        } else {
          default_value
        }
      }
      Some(":+") => {
        if truthy {
          default_value
        } else {
          String::new()
        }
      }
      Some("+") => {
        if is_set {
          default_value
        } else {
          String::new()
        }
      }
      _ => {
        if truthy {
          env_value.unwrap_or("").to_string()
        } else {
          String::new()
        }
      }
    };

    // Replace the first literal occurrence of the template (which may be an
    // escaped one before the regex match); `$`-patterns are live. The budget is
    // enforced inside the replace, so the transient allocation stays bounded
    // even when a single `$'`-heavy replacement would multiply the tail.
    match js_string_replace_first(&result, &template, &replacement, opts.max_output_bytes) {
      Replaced::Value(next) => result = next,
      Replaced::Absent => break, // unreachable: the template was just matched
      Replaced::TooLarge => {
        return Err(ExpandError {
          max_output_bytes: opts.max_output_bytes,
        })
      }
    }

    // Break (a): whole result equals env[name] of the just-expanded name.
    if let Some(v) = env_get(&name) {
      if result == v {
        break;
      }
    }
    // Break (b): literals guard (truthy literal containing a `$` pattern).
    if let Some(literal) = opts.literals.get(&name) {
      if !literal.is_empty() && LITERAL_PATTERN_RE.is_match(literal) {
        break;
      }
    }
  }
  Ok(result)
}

/// Iteration cap that bounds the non-terminating expansion class (see
/// [`expand`]). One iteration is one replacement; real files need at most a few
/// per `$` reference (DEEP8's 5-level nesting uses about 10 total), so 10k clears
/// every terminating input while cutting off the self-reinserting class cheaply.
#[cfg(not(fuzzing))]
pub const MAX_EXPAND_ITERATIONS: usize = 10_000;

/// Fuzz-only iteration cap (`--cfg fuzzing`; see docs/envrypt/fuzzing.md). The
/// additive self-reinserting case does O(cap²) work (each iteration
/// `String.replace`s over an ever-larger string): at the production cap a single
/// exec runs for tens of seconds even on a ≤128-byte input (minutes under ASan),
/// tripping every finite libFuzzer `-timeout`. Lowering the cap keeps the same
/// scan → look-up → `js_string_replace_first` path fuzzed on grown strings while
/// every exec stays fast.
///
/// The lowered cap does not cover the multiplicative case (a `$'`/`$&` value
/// whose after-match/whole-match reinsertion duplicates a still-`${…}`-bearing
/// tail): it grows `result` exponentially per pass, past any iteration cap.
/// [`DEFAULT_MAX_EXPAND_OUTPUT_BYTES`] is the companion output-size guard that
/// bounds it, and is likewise lowered under this cfg.
#[cfg(fuzzing)]
pub const MAX_EXPAND_ITERATIONS: usize = 256;

/// The default byte budget for one expanded value ([`ExpandOptions`] carries the
/// effective one, and [`crate::LoadOptions::max_expand_output_bytes`] sets it).
/// The multiplicative `$'`/`` $` ``/`$&` self-reinserting case doubles `result`
/// every pass and so blows past any iteration cap; without a size budget a
/// KB-scale `.env` value exhausts host memory in about 31 passes. 1 MiB is three
/// orders of magnitude above any real `.env` value, and the budget is enforced
/// inside [`js_string_replace_first`], so the transient allocation of even a
/// pathological `$'`-dense replacement stays within about twice the budget.
#[cfg(not(fuzzing))]
pub const DEFAULT_MAX_EXPAND_OUTPUT_BYTES: usize = 1 << 20; // 1 MiB

/// Fuzz-lowered [`DEFAULT_MAX_EXPAND_OUTPUT_BYTES`] (`--cfg fuzzing`; see
/// docs/envrypt/fuzzing.md). 16 KiB is 4x the fuzz `-max_len` (4096), ample to
/// fuzz grown-string behavior, and keeps every exec far under
/// `-rss_limit_mb=2048`.
#[cfg(fuzzing)]
pub const DEFAULT_MAX_EXPAND_OUTPUT_BYTES: usize = 1 << 14; // 16 KiB

/// The outcome of [`js_string_replace_first`].
pub(crate) enum Replaced {
  /// `search` is absent from the haystack.
  Absent,
  /// The replaced string.
  Value(String),
  /// The replaced string would exceed the caller's byte budget, so it was never
  /// built.
  TooLarge,
}

/// JS `String.prototype.replace(searchString, replacement)` — replaces the FIRST
/// literal occurrence of `search`, applying the ECMA-262 `GetSubstitution`
/// patterns for string-search replace: `$$` → `$`, `$&` → matched text,
/// `` $` `` → text before the match, `$'` → text after the match; every other `$`
/// (incl. `$1`, `$<`) stays literal.
///
/// The result may not exceed `max_output_bytes`. The budget is checked as the
/// output is assembled rather than after, so a replacement carrying many `$'`
/// patterns — each of which reinserts the whole after-match tail — cannot
/// allocate an arbitrarily large intermediate before anyone notices.
pub(crate) fn js_string_replace_first(
  haystack: &str,
  search: &str,
  replacement: &str,
  max_output_bytes: usize,
) -> Replaced {
  let Some(pos) = haystack.find(search) else {
    return Replaced::Absent;
  };
  let before = &haystack[..pos];
  let after = &haystack[pos + search.len()..];

  let mut out = String::with_capacity(haystack.len() + replacement.len());
  // Appends `piece` unless it would push `out` past the budget.
  macro_rules! push_bounded {
    ($piece:expr) => {{
      let piece: &str = $piece;
      if out.len() + piece.len() > max_output_bytes {
        return Replaced::TooLarge;
      }
      out.push_str(piece);
    }};
  }

  push_bounded!(before);
  // ECMA-262 GetSubstitution over the replacement, string-search flavor
  // (no capture groups: `$1`/`$<` stay literal).
  let bytes = replacement.as_bytes();
  let mut i = 0;
  let mut seg = 0;
  while i < bytes.len() {
    if bytes[i] == b'$' && i + 1 < bytes.len() {
      let (rep, skip): (Option<&str>, usize) = match bytes[i + 1] {
        b'$' => (Some("$"), 2),
        b'&' => (Some(search), 2),
        b'`' => (Some(before), 2),
        b'\'' => (Some(after), 2),
        _ => (None, 1),
      };
      if let Some(r) = rep {
        push_bounded!(&replacement[seg..i]);
        push_bounded!(r);
        i += skip;
        seg = i;
        continue;
      }
    }
    i += 1;
  }
  push_bounded!(&replacement[seg..]);
  push_bounded!(after);
  Replaced::Value(out)
}

#[cfg(test)]
mod tests {
  // Pins the expansion tables and quirks. The full-pipeline expansion tests
  // live in parse/mod.rs.
  use super::*;

  fn env(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    pairs
      .iter()
      .map(|(k, v)| (k.to_string(), v.to_string()))
      .collect()
  }

  fn options<'a>(
    process_env: &'a IndexMap<String, String>,
    empty: &'a IndexMap<String, String>,
  ) -> ExpandOptions<'a> {
    ExpandOptions {
      overload: false,
      process_env,
      running_parsed: empty,
      literals: empty,
      max_output_bytes: DEFAULT_MAX_EXPAND_OUTPUT_BYTES,
    }
  }

  fn expand_env(value: &str, process_env: &IndexMap<String, String>) -> String {
    let empty = IndexMap::new();
    expand(value, &options(process_env, &empty)).expect("expansion stays within the byte budget")
  }

  #[test]
  fn operator_table() {
    // Operator table (SET='val', EMPTY='', UNSET absent).
    let e = env(&[("SET", "val"), ("EMPTY", "")]);
    assert_eq!(expand_env("${EMPTY:-def}", &e), "def");
    assert_eq!(expand_env("${UNSET:-def}", &e), "def");
    assert_eq!(expand_env("${EMPTY-def}", &e), "");
    assert_eq!(expand_env("${UNSET-def}", &e), "def");
    assert_eq!(expand_env("${EMPTY:+alt}", &e), "");
    assert_eq!(expand_env("${SET:+alt}", &e), "alt");
    assert_eq!(expand_env("${EMPTY+alt}", &e), "alt");
    assert_eq!(expand_env("${UNSET+alt}", &e), "");
    assert_eq!(expand_env("${UNSET}", &e), "");
    assert_eq!(expand_env("${SET}", &e), "val");
    assert_eq!(expand_env("$SET", &e), "val");
  }

  #[test]
  fn first_op_wins_and_split_on_all_occurrences() {
    // `${MY-VAR:-def}`: first op `-` at index 2 → name `MY`, default
    // `VAR:-def` (rejoined).
    assert_eq!(expand_env("${MY-VAR:-def}", &env(&[])), "VAR:-def");
    assert_eq!(expand_env("${MY-VAR:-def}", &env(&[("MY", "m")])), "m");
  }

  #[test]
  fn unbraced_name_stops_at_colon() {
    // An unbraced `$UNDEFINED:-...` does not treat `:-` as an operator.
    assert_eq!(
      expand_env("$UNDEFINED:-/default/path", &env(&[])),
      ":-/default/path"
    );
  }

  #[test]
  fn split_null_quirk() {
    // `expression.split(null)` splits on the literal string "null".
    let e = env(&[("SET", "val")]);
    assert_eq!(expand_env("${SETnullX}", &e), "val");
    assert_eq!(expand_env("$SETnullX", &e), "val");
  }

  #[test]
  fn self_reference_break() {
    // Break (a): stops when the entire result equals env[name].
    assert_eq!(expand_env("${SET}", &env(&[("SET", "${SET}")])), "${SET}");
    assert_eq!(
      expand_env("${A}", &env(&[("A", "${B}"), ("B", "deep")])),
      "${B}"
    );
    assert_eq!(
      expand_env("-${A}", &env(&[("A", "${B}"), ("B", "deep")])),
      "-deep"
    );
  }

  #[test]
  fn literals_guard_stops_after_first_replacement() {
    // Break (b): with single-quoted literal L='$X', `${L}${L}` stops after the
    // first replacement.
    let e = env(&[("L", "$X"), ("X", "val")]);
    let lits = env(&[("L", "$X")]);
    let empty = IndexMap::new();
    let got = expand(
      "${L}${L}",
      &ExpandOptions {
        literals: &lits,
        ..options(&e, &empty)
      },
    )
    .unwrap();
    assert_eq!(got, "$X${L}");
  }

  #[test]
  fn replacement_dollar_patterns_are_live() {
    // `$$` collapses, then the produced `$b` re-matches; `$'` inserts the text
    // after the match.
    assert_eq!(expand_env("${SET}", &env(&[("SET", "a$$b")])), "a");
    assert_eq!(
      expand_env("pre ${SET} post", &env(&[("SET", "x$'y")])),
      "pre x posty post"
    );
  }

  #[test]
  fn string_replace_hits_earlier_escaped_occurrence() {
    // `\${SET} ${SET}`: the regex matches the unescaped occurrence, but
    // String.replace substitutes the first literal one (the escaped one),
    // giving `\val val`.
    assert_eq!(
      expand_env("\\${SET} ${SET}", &env(&[("SET", "val")])),
      "\\val val"
    );
  }

  #[test]
  fn lookbehind_blocks_escaped_dollar() {
    // `\$` is not expanded; parse unescapes it later.
    assert_eq!(expand_env("\\$SET", &env(&[("SET", "val")])), "\\$SET");
    assert_eq!(expand_env("\\${SET}", &env(&[("SET", "val")])), "\\${SET}");
  }

  #[test]
  fn nested_defaults_resolve_inner_first() {
    let e = env(&[("SET", "s")]);
    assert_eq!(expand_env("${SET:-${UNSET:-x}}", &e), "s");
    assert_eq!(expand_env("${UNSET:-${U2:-x}}", &env(&[])), "x");
  }

  #[test]
  fn non_matches_left_literal() {
    let e = env(&[("A", "v")]);
    assert_eq!(expand_env("${}", &e), "${}");
    assert_eq!(expand_env("${A", &e), "${A");
    assert_eq!(expand_env("$", &e), "$");
    assert_eq!(expand_env("$2foo", &e), "$2foo");
  }

  #[test]
  fn overload_flips_env_merge() {
    // Default: processEnv wins. Overload: runningParsed wins.
    let pe = env(&[("X", "fromPE")]);
    let rp = env(&[("X", "fromRP")]);
    let empty = IndexMap::new();
    let default = expand(
      "${X}",
      &ExpandOptions {
        running_parsed: &rp,
        ..options(&pe, &empty)
      },
    )
    .unwrap();
    assert_eq!(default, "fromPE");
    let overload = expand(
      "${X}",
      &ExpandOptions {
        overload: true,
        running_parsed: &rp,
        ..options(&pe, &empty)
      },
    )
    .unwrap();
    assert_eq!(overload, "fromRP");
  }

  #[test]
  fn js_nonterminating_inputs_hit_the_iteration_cap() {
    // These inputs never terminate: the loop caps at MAX_EXPAND_ITERATIONS
    // instead of hanging, so only termination is asserted. `SET='$&'` is the
    // constant-size member (`$&` reinserts the matched `${SET}` verbatim each
    // iteration); `SET='x$&y'` is the growing-string member, same loop, left
    // out of the test for speed.
    let _ = expand_env("X ${SET}", &env(&[("SET", "${SET}")]));
    let _ = expand_env("${SET}", &env(&[("SET", "$&")]));
  }

  // The multiplicative `$'`/`$&` self-reinserting case: the after-match `$'`
  // duplicates a still-`${…}`-bearing tail, so `result` doubles every pass.
  // The iteration cap bounds only the additive case's O(cap²) time, never this
  // case's memory, so the byte budget is what stops it — loudly, with an error,
  // rather than by growing until the host runs out of memory. The committed seed
  // `fuzz/corpus/parse_pipeline/craft-expand-multiplicative` drives the same
  // input through the fuzz target.
  #[test]
  fn multiplicative_expand_exceeds_the_byte_budget_and_errors() {
    // SET carries a live `${SET}` (escaped through expand, unescaped by parse)
    // plus a `$'`, so expanding `${SET}${SET}` duplicates the `${…}`-bearing
    // tail every pass.
    let e = env(&[("SET", "${SET}$'x")]);
    let empty = IndexMap::new();
    let err = expand("${SET}${SET}", &options(&e, &empty))
      .expect_err("the doubling expansion must exceed the byte budget");
    assert_eq!(err.max_output_bytes, DEFAULT_MAX_EXPAND_OUTPUT_BYTES);
  }

  #[test]
  fn a_small_budget_bounds_the_work_and_never_truncates() {
    // The budget is a hard stop, not a truncation point: an expansion that
    // cannot fit returns the error, and no partial value escapes.
    let e = env(&[("SET", "${SET}$'x")]);
    let empty = IndexMap::new();
    let err = expand(
      "${SET}${SET}",
      &ExpandOptions {
        max_output_bytes: 64,
        ..options(&e, &empty)
      },
    )
    .expect_err("the doubling expansion must exceed a 64-byte budget");
    assert_eq!(err.max_output_bytes, 64);

    // A value that fits is untouched by the budget.
    let e = env(&[("SET", "val")]);
    let got = expand(
      "${SET}",
      &ExpandOptions {
        max_output_bytes: 64,
        ..options(&e, &empty)
      },
    )
    .unwrap();
    assert_eq!(got, "val");
  }

  fn replaced(haystack: &str, search: &str, replacement: &str) -> Option<String> {
    match js_string_replace_first(
      haystack,
      search,
      replacement,
      DEFAULT_MAX_EXPAND_OUTPUT_BYTES,
    ) {
      Replaced::Value(v) => Some(v),
      Replaced::Absent => None,
      Replaced::TooLarge => panic!("the budget is far above these inputs"),
    }
  }

  #[test]
  fn js_string_replace_first_substitution_patterns() {
    // ECMA-262 GetSubstitution for string-search replace.
    assert_eq!(replaced("a-b-c", "-", "$$").as_deref(), Some("a$b-c"));
    assert_eq!(replaced("a-b", "-", "[$&]").as_deref(), Some("a[-]b"));
    assert_eq!(replaced("a-b", "-", "[$`]").as_deref(), Some("a[a]b"));
    assert_eq!(replaced("a-b", "-", "[$']").as_deref(), Some("a[b]b"));
    // `$1`/`$<` stay literal for string-search replace; lone/trailing `$` too.
    assert_eq!(
      replaced("a-b", "-", "$1$<x>$").as_deref(),
      Some("a$1$<x>$b")
    );
    assert_eq!(replaced("a-b", "z", "r"), None);
  }

  #[test]
  fn js_string_replace_first_stops_at_the_budget() {
    // The budget is enforced while the output is assembled, so an oversized
    // result is never materialized.
    assert!(matches!(
      js_string_replace_first("a-b", "-", "0123456789", 8),
      Replaced::TooLarge
    ));
    assert!(matches!(
      js_string_replace_first("a-b", "-", "x", 3),
      Replaced::Value(_)
    ));
  }
}
