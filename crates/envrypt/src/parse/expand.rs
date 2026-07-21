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
}

/// Expands `${VAR}` and `$VAR` references in `value`.
///
/// A class of self-reinserting replacements (for example `$&` in an env value, or
/// `expand("X ${SET}")` with `SET='${SET}'`) never terminates. The loop caps at
/// [`MAX_EXPAND_ITERATIONS`] replacements and returns the current result; every
/// terminating input finishes far below the cap.
pub fn expand(value: &str, opts: &ExpandOptions) -> String {
  // EXPAND_RE cannot match without a `$` byte.
  if memchr::memchr(b'$', value.as_bytes()).is_none() {
    return value.to_string();
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
    // escaped one before the regex match); `$`-patterns are live.
    match js_string_replace_first(&result, &template, &replacement) {
      Some(next) => result = next,
      None => break, // unreachable: the template was just matched
    }

    // Fuzz-only output-size guard, companion to the lowered
    // `MAX_EXPAND_ITERATIONS` (see docs/envrypt/fuzzing.md). The
    // multiplicative `$'`/`$&` self-reinserting case (a value whose
    // after-match/whole-match reinsertion duplicates a still-`${…}`-bearing
    // tail) grows `result` exponentially per pass, so it OOM-aborts the fuzzer
    // long before any iteration cap; the cap bounds only the additive case's
    // O(cap²) time, never this case's memory. Under `--cfg fuzzing`, truncate
    // to a small byte budget and stop, so the same scan → look-up → replace
    // body still runs on grown strings without OOM. Truncating here keeps
    // every stored `running_parsed` value within the budget, so a later line's
    // replacement cannot re-explode. Production has no size cap. See
    // `FUZZ_MAX_EXPAND_OUTPUT_BYTES`.
    #[cfg(fuzzing)]
    if result.len() > FUZZ_MAX_EXPAND_OUTPUT_BYTES {
      let mut end = FUZZ_MAX_EXPAND_OUTPUT_BYTES;
      while !result.is_char_boundary(end) {
        end -= 1;
      }
      result.truncate(end);
      break;
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
  result
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
/// The lowered cap does not cover everything. The multiplicative case (a
/// `$'`/`$&` value whose after-match/whole-match reinsertion duplicates a
/// still-`${…}`-bearing tail) grows `result` exponentially per pass and
/// OOM-aborts the fuzzer at about 31 passes, past any iteration cap.
/// [`FUZZ_MAX_EXPAND_OUTPUT_BYTES`] is the companion output-size guard that bounds
/// it.
///
/// Both guards match the `parse::evaluate` command-substitution stub: fuzz-only,
/// no change to any shipped build. Production keeps the 10k cap and no size cap,
/// so on this hostile input it stays non-terminating or OOMs, which is the frozen
/// expansion behavior.
#[cfg(fuzzing)]
pub const MAX_EXPAND_ITERATIONS: usize = 256;

/// Fuzz-only output-size guard, companion to the lowered
/// [`MAX_EXPAND_ITERATIONS`] (`--cfg fuzzing`; see docs/envrypt/fuzzing.md).
/// Bounds the intermediate `expand` result so the multiplicative `$'`/`$&`
/// self-reinserting case terminates without OOM (it grows the string
/// exponentially per pass, past any iteration cap). 16 KiB is 4x the fuzz
/// `-max_len` (4096), ample to fuzz grown-string behavior, and keeps even a
/// pathological single `js_string_replace_first` call (result within budget,
/// replacement within budget with about 8K `$'`, each duplicating a ≤16 KiB tail
/// → ≤128 MiB transient) well under `-rss_limit_mb=2048`. The truncate-and-break
/// at the call site keeps every stored value within this bound so it cannot
/// re-explode. Production has no such cap (see [`MAX_EXPAND_ITERATIONS`]).
#[cfg(fuzzing)]
const FUZZ_MAX_EXPAND_OUTPUT_BYTES: usize = 1 << 14; // 16 KiB

/// JS `String.prototype.replace(searchString, replacement)` — replaces the FIRST
/// literal occurrence of `search`, applying the ECMA-262 `GetSubstitution`
/// patterns for string-search replace: `$$` → `$`, `$&` → matched text,
/// `` $` `` → text before the match, `$'` → text after the match; every other `$`
/// (incl. `$1`, `$<`) stays literal. Returns `None` when `search` is absent.
pub(crate) fn js_string_replace_first(
  haystack: &str,
  search: &str,
  replacement: &str,
) -> Option<String> {
  let pos = haystack.find(search)?;
  let before = &haystack[..pos];
  let after = &haystack[pos + search.len()..];

  let mut out = String::with_capacity(haystack.len() + replacement.len());
  out.push_str(before);
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
        out.push_str(&replacement[seg..i]);
        out.push_str(r);
        i += skip;
        seg = i;
        continue;
      }
    }
    i += 1;
  }
  out.push_str(&replacement[seg..]);
  out.push_str(after);
  Some(out)
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

  fn expand_env(value: &str, process_env: &IndexMap<String, String>) -> String {
    let empty = IndexMap::new();
    expand(
      value,
      &ExpandOptions {
        overload: false,
        process_env,
        running_parsed: &empty,
        literals: &empty,
      },
    )
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
        overload: false,
        process_env: &e,
        running_parsed: &empty,
        literals: &lits,
      },
    );
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
        overload: false,
        process_env: &pe,
        running_parsed: &rp,
        literals: &empty,
      },
    );
    assert_eq!(default, "fromPE");
    let overload = expand(
      "${X}",
      &ExpandOptions {
        overload: true,
        process_env: &pe,
        running_parsed: &rp,
        literals: &empty,
      },
    );
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

  // Regression for the multiplicative `$'`/`$&` self-reinserting case (see
  // docs/envrypt/fuzzing.md): the after-match `$'` duplicates a
  // still-`${…}`-bearing tail, so `result` grows exponentially per pass and can
  // OOM. The lowered iteration cap bounds only the additive case's O(cap²) time,
  // never this case's memory, so the fuzz build adds
  // `FUZZ_MAX_EXPAND_OUTPUT_BYTES`. This `#[cfg(fuzzing)]` test pins that guard;
  // run it with `RUSTFLAGS="--cfg fuzzing" cargo test -p envrypt`. The committed
  // seed `fuzz/corpus/parse_pipeline/craft-expand-multiplicative` gives the
  // nightly coverage of the same input.
  #[cfg(fuzzing)]
  #[test]
  fn fuzz_multiplicative_expand_is_size_bounded() {
    // SET carries a live `${SET}` (escaped through expand, unescaped by parse)
    // plus a `$'`, so expanding `${SET}${SET}` duplicates the `${…}`-bearing
    // tail every pass.
    let out = expand_env("${SET}${SET}", &env(&[("SET", "${SET}$'x")]));
    // The output-size guard truncates and breaks, so the result stays within
    // the budget (a normal build would grow it until OOM).
    assert!(
      out.len() <= FUZZ_MAX_EXPAND_OUTPUT_BYTES,
      "fuzzing output-size guard must bound the multiplicative case \
             (len={})",
      out.len()
    );
  }

  #[test]
  fn js_string_replace_first_substitution_patterns() {
    // ECMA-262 GetSubstitution for string-search replace.
    assert_eq!(
      js_string_replace_first("a-b-c", "-", "$$").as_deref(),
      Some("a$b-c")
    );
    assert_eq!(
      js_string_replace_first("a-b", "-", "[$&]").as_deref(),
      Some("a[-]b")
    );
    assert_eq!(
      js_string_replace_first("a-b", "-", "[$`]").as_deref(),
      Some("a[a]b")
    );
    assert_eq!(
      js_string_replace_first("a-b", "-", "[$']").as_deref(),
      Some("a[b]b")
    );
    // `$1`/`$<` stay literal for string-search replace; lone/trailing `$` too.
    assert_eq!(
      js_string_replace_first("a-b", "-", "$1$<x>$").as_deref(),
      Some("a$1$<x>$b")
    );
    assert_eq!(js_string_replace_first("a-b", "z", "r"), None);
  }
}
