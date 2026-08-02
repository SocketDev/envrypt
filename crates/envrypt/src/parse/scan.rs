//! `scan()` — the .env line tokenizer.
//!
//! The grammar matches JavaScript's `.env` parsing so encrypted files stay
//! interoperable. Four JS-regex details the Rust translation must honor:
//! * JS `\s` includes U+FEFF (BOM) and excludes U+0085 (NEL), so Rust's built-in
//!   `\s` cannot stand in; every `\s` in the LINE regex is the explicit [`JS_WS`]
//!   class.
//! * JS `\w` is ASCII-only, so the key class is spelled `[0-9A-Za-z_.-]`.
//! * JS multiline `^`/`$` anchor at every LineTerminator (`\n`, `\r`, U+2028,
//!   U+2029); Rust `(?m)` anchors only at `\n`, so the anchors are explicit
//!   lookarounds (fancy-regex).
//! * The quoted-value alternatives backtrack into the unquoted `[^#\r\n]+` branch
//!   (`A="x" trailing` keeps its quotes); fancy-regex's backtracking engine
//!   reproduces the JS alternative order.

use indexmap::IndexMap;

use std::borrow::Cow;
use std::sync::LazyLock;

/// The JS `\s` class, spelled out (ECMA-262 WhiteSpace ∪ LineTerminator):
/// `\t \v \f space U+00A0 U+FEFF`, Unicode Zs, and `\n \r U+2028 U+2029`. It
/// includes U+FEFF and excludes U+0085, where Rust's `\s` does the opposite.
const JS_WS: &str = r"[ \t\n\x0B\x0C\r\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}\u{FEFF}]";

/// JS multiline `^`: start of text or right after any LineTerminator (`\n`, `\r`,
/// U+2028, U+2029). Rust `(?m)^` handles only `\n`, so this uses an explicit
/// lookbehind.
const LINE_START: &str = r"(?:\A|(?<=[\n\r\u{2028}\u{2029}]))";

/// JS multiline `$`: end of text or right before any LineTerminator.
const LINE_END: &str = r"(?:\z|(?=[\n\r\u{2028}\u{2029}]))";

/// JS `.` (no dotall): any char other than a LineTerminator. Rust `.` excludes
/// only `\n`, so this spells the class out.
const JS_DOT: &str = r"[^\n\r\u{2028}\u{2029}]";

/// The LINE regex. Source pattern:
/// ```text
/// /(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/mg
/// ```
/// Translated construct-for-construct: `\s` → [`JS_WS`], `[\w.-]` → ASCII class,
/// `^`/`$`(m) → [`LINE_START`]/[`LINE_END`] (the doubled `(?:^|^)`/`(?:$|$)` are
/// redundant), `.` → [`JS_DOT`]. fancy-regex supplies the backtracking
/// alternative order.
pub(crate) static LINE: LazyLock<fancy_regex::Regex> = LazyLock::new(|| {
    let pattern = format!(
        r##"{ls}{ws}*(?:export{ws}+)?([0-9A-Za-z_.-]+)(?:{ws}*={ws}*?|:{ws}+?)({ws}*'(?:\\'|[^'])*'|{ws}*"(?:\\"|[^"])*"|{ws}*`(?:\\`|[^`])*`|[^#\r\n]+)?{ws}*(?:#{dot}*)?{le}"##,
        ls = LINE_START,
        ws = JS_WS,
        dot = JS_DOT,
        le = LINE_END,
    );
    fancy_regex::Regex::new(&pattern).expect("LINE regex compiles")
});

/// clean()'s outer-quote strip: `/^(['"`])([\s\S]*)\1$/mg`, with the multiline
/// anchors spelled as lookarounds.
static STRIP_QUOTES: LazyLock<fancy_regex::Regex> = LazyLock::new(|| {
    let pattern = format!(
        r##"{ls}(['"`])([\s\S]*)\1{le}"##,
        ls = LINE_START,
        le = LINE_END,
    );
    fancy_regex::Regex::new(&pattern).expect("STRIP_QUOTES regex compiles")
});

/// Is `c` in the JS `\s` set? (Keep in sync with [`JS_WS`].)
pub(crate) fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t' | '\n' | '\x0B' | '\x0C' | '\r' | '\u{00A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

/// Normalizes newlines: every `\r` becomes `\n`, consuming one
/// immediately-following `\n`.
fn convert_windows_newlines(src: &str) -> Cow<'_, str> {
    // The replace cannot match without a `\r` byte.
    if memchr::memchr(b'\r', src.as_bytes()).is_none() {
        return Cow::Borrowed(src);
    }
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// The detected quote of a raw scanned value: the first char of the trimmed raw
/// match.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Quote {
    #[default]
    None,
    Single,
    Double,
    Backtick,
}

/// Options for [`scan`].
#[derive(Clone, Debug)]
pub struct ScanOptions {
    /// Normalize `\r\n?` to `\n` before scanning. Default `true`.
    pub convert_windows_newlines: bool,
    /// Expand `\n`/`\r`/`\t` escapes in double-quoted values. Default `true`.
    pub expand_double_quoted_newlines: bool,
    /// Include-key glob patterns.
    pub ik: Vec<String>,
    /// Exclude-key glob patterns; ek wins over ik.
    pub ek: Vec<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            convert_windows_newlines: true,
            expand_double_quoted_newlines: true,
            ik: Vec::new(),
            ek: Vec::new(),
        }
    }
}

/// One tokenizer match handed to the `transform` callback: name, cleaned value,
/// and quote. It borrows from the (possibly newline-normalized) scan text;
/// `value` stays `Cow::Borrowed` when no quote-strip or escape-expansion runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanEntry<'src> {
    pub name: &'src str,
    pub value: Cow<'src, str>,
    pub quote: Quote,
}

/// Scans `src` and returns every occurrence of every key, in file order.
pub fn scan(src: &str, opts: &ScanOptions) -> IndexMap<String, Vec<String>> {
    scan_with(src, opts, |entry| entry.value.to_string())
}

/// Scans `src`, calling `transform` on each match; its return value is pushed into
/// that key's list. The parse pipeline runs its per-entry step machine through
/// this callback.
pub fn scan_with<T>(
    src: &str,
    opts: &ScanOptions,
    mut transform: impl FnMut(&ScanEntry<'_>) -> T,
) -> IndexMap<String, Vec<T>> {
    let lines: Cow<'_, str> = if opts.convert_windows_newlines {
        convert_windows_newlines(src)
    } else {
        Cow::Borrowed(src)
    };

    // Build the ik/ek matcher pair once per call. An invalid key glob panics
    // through this infallible signature; callers that accept user input
    // pre-validate via `edit::KeyFilter::new`.
    let filter = crate::edit::KeyFilter::new(&opts.ik, &opts.ek).unwrap_or_else(|e| panic!("{e}"));

    let mut parsed: IndexMap<String, Vec<T>> = IndexMap::new();
    for caps in LINE.captures_iter(&lines) {
        // The backtracking limit is unreachable for sane inputs. On an
        // adversarial unterminated-quote plus backslash-run input, stop scanning
        // rather than panic; such inputs run exponentially long (an effective
        // hang) either way.
        let Ok(caps) = caps else { break };
        let name = caps.get(1).expect("group 1 is non-optional").as_str();
        if filter.skips(name) {
            continue;
        }
        let raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let quote = get_quote(raw);
        let value = clean(raw, quote, opts.expand_double_quoted_newlines);
        let entry = ScanEntry { name, value, quote };
        let transformed = transform(&entry);
        parsed
            .entry(entry.name.to_string())
            .or_default()
            .push(transformed);
    }
    parsed
}

/// Trims the JS WhiteSpace ∪ LineTerminator set (U+FEFF included, U+0085
/// excluded), which differs from `char::is_whitespace`.
pub(crate) fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_whitespace)
}

/// Classifies the quote: trim `raw`, then read its first character.
pub(crate) fn get_quote(raw: &str) -> Quote {
    match js_trim(raw).chars().next() {
        Some('\'') => Quote::Single,
        Some('"') => Quote::Double,
        Some('`') => Quote::Backtick,
        _ => Quote::None,
    }
}

/// Cleans a raw value: trim both ends, strip one pair of matching surrounding
/// quotes, then expand `\n`/`\r`/`\t` escapes for double-quoted values only.
pub(crate) fn clean(raw: &str, quote: Quote, expand_double_quoted_newlines: bool) -> Cow<'_, str> {
    let trimmed = js_trim(raw);
    let mut v = STRIP_QUOTES.replace_all(trimmed, |caps: &fancy_regex::Captures<'_>| {
        caps.get(2)
            .expect("group 2 always participates")
            .as_str()
            .to_string()
    });
    // Each escape pattern (`\\n`, `\\r`, `\\t`) begins with a backslash, so
    // without one the replace chain is an identity.
    if quote == Quote::Double
        && expand_double_quoted_newlines
        && memchr::memchr(b'\\', v.as_bytes()).is_some()
    {
        // Sequential literal replaces. `\\n` contains the substring `\n`, so a
        // doubled backslash before `n` yields a backslash plus a real LF.
        v = Cow::Owned(
            v.replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t"),
        );
    }
    v
}

#[cfg(test)]
mod tests {
    // Pins the tokenizer alone. The full-pipeline tests live in parse/mod.rs.
    use super::*;

    fn scan_default(src: &str) -> IndexMap<String, Vec<String>> {
        scan(src, &ScanOptions::default())
    }

    fn first(src: &str, key: &str) -> String {
        scan_default(src)
            .get(key)
            .unwrap_or_else(|| panic!("key {key:?} not parsed from {src:?}"))[0]
            .clone()
    }

    fn quote_of(src: &str, key: &str) -> Quote {
        let mut found = Quote::None;
        scan_with(src, &ScanOptions::default(), |e| {
            if e.name == key {
                found = e.quote;
            }
            e.value.to_string()
        });
        found
    }

    #[test]
    fn hash_inside_quotes_kept_and_real_comment_stripped() {
        // A `#` inside quotes is part of the value; the trailing `# real comment`
        // is stripped.
        assert_eq!(
            first("A=\"hello # not comment\" # real comment", "A"),
            "hello # not comment"
        );
    }

    #[test]
    fn trailing_comment_stripped_from_unquoted() {
        assert_eq!(first("B=unquoted # comment", "B"), "unquoted");
    }

    #[test]
    fn hash_cuts_unquoted_value_without_space() {
        assert_eq!(first("C=va#lue", "C"), "va");
    }

    #[test]
    fn unterminated_quote_retained_and_classified_double() {
        // An unterminated quote keeps its quote char; getQuote reads the raw
        // capture, so the entry classifies as double-quoted.
        assert_eq!(first("J=\"unterminated", "J"), "\"unterminated");
        assert_eq!(quote_of("J=\"unterminated", "J"), Quote::Double);
    }

    #[test]
    fn empty_and_quoted_empty_values() {
        assert_eq!(first("K=", "K"), "");
        assert_eq!(first("K=''", "K"), "");
        assert_eq!(first("K=\"\"", "K"), "");
        assert_eq!(first("K=``", "K"), "");
    }

    #[test]
    fn duplicates_kept_in_file_order() {
        let parsed = scan_default("L=one\nL=two");
        assert_eq!(
            parsed.get("L").unwrap(),
            &vec!["one".to_string(), "two".to_string()]
        );
    }

    #[test]
    fn quoted_then_garbage_backtracks_to_unquoted() {
        // The quoted alternative fails overall, so the engine backtracks to
        // `[^#\r\n]+` and keeps the quote chars.
        assert_eq!(first("A=\"x\" trailing", "A"), "\"x\" trailing");
        assert_eq!(quote_of("A=\"x\" trailing", "A"), Quote::Double);
    }

    #[test]
    fn multiline_double_quoted_keeps_inner_hash() {
        assert_eq!(
            first("O=\"multi\nline # keep\nend\"", "O"),
            "multi\nline # keep\nend"
        );
    }

    #[test]
    fn separator_whitespace_crosses_newlines() {
        // `\s*` around `=` crosses newlines, since JS `\s` includes `\n`.
        assert_eq!(first("KEY\n=split", "KEY"), "split");
    }

    #[test]
    fn colon_separator_requires_tight_colon_then_space() {
        assert_eq!(first("F: colon-value", "F"), "colon-value");
        assert!(scan_default("F:x").is_empty(), "`F:x` must not match");
        assert!(
            scan_default("K :  v").is_empty(),
            "space before `:` kills it"
        );
    }

    #[test]
    fn malformed_line_blocks_later_pairs_on_same_line() {
        // `A B=v` parses nothing; the regex can only start at a line start.
        assert!(scan_default("A B=v").is_empty());
    }

    #[test]
    fn outer_whitespace_trimmed_before_quote_strip() {
        assert_eq!(first("U= \"padded\" ", "U"), "padded");
    }

    #[test]
    fn comments_and_blank_lines_produce_no_match() {
        assert!(scan_default("#comment\n\n# another\n").is_empty());
    }

    #[test]
    fn export_prefix_forms() {
        // `export ` is an optional prefix: `export  KEY=v` → KEY,
        // `exportKEY=v` → exportKEY, `export=1` → key `export`.
        assert_eq!(first("export  KEY=v", "KEY"), "v");
        assert_eq!(first("exportKEY=v", "exportKEY"), "v");
        assert_eq!(first("export=1", "export"), "1");
    }

    #[test]
    fn keys_may_start_with_digits_and_contain_dots_dashes() {
        assert_eq!(first("2START=v", "2START"), "v");
        assert_eq!(
            first("POSTGRESQL.MAIN.USER=postgres", "POSTGRESQL.MAIN.USER"),
            "postgres"
        );
        assert_eq!(first("MY-KEY=v", "MY-KEY"), "v");
        assert_eq!(first("lower_case=v", "lower_case"), "v");
    }

    #[test]
    fn cr_and_crlf_normalized_by_default() {
        for src in [
            "SERVER=localhost\rPASSWORD=password\rDB=tests\r",
            "SERVER=localhost\nPASSWORD=password\nDB=tests\n",
            "SERVER=localhost\r\nPASSWORD=password\r\nDB=tests\r\n",
        ] {
            let parsed = scan_default(src);
            assert_eq!(parsed.get("SERVER").unwrap()[0], "localhost");
            assert_eq!(parsed.get("PASSWORD").unwrap()[0], "password");
            assert_eq!(parsed.get("DB").unwrap()[0], "tests");
        }
    }

    #[test]
    fn crlf_conversion_can_be_disabled() {
        // With newline conversion off, the multiline `^` still matches after `\r`,
        // so both keys tokenize; values stop at `[^#\r\n]+`.
        let opts = ScanOptions {
            convert_windows_newlines: false,
            ..Default::default()
        };
        let parsed = scan("A=1\r\nB=2\rC=3", &opts);
        assert_eq!(parsed.get("A").unwrap()[0], "1");
        assert_eq!(parsed.get("B").unwrap()[0], "2");
        assert_eq!(parsed.get("C").unwrap()[0], "3");
    }

    #[test]
    fn escape_expansion_double_quoted_only() {
        assert_eq!(
            first("A=\"expand\\nnew\\nlines\"", "A"),
            "expand\nnew\nlines"
        );
        assert_eq!(
            first("A=dontexpand\\nnewlines", "A"),
            "dontexpand\\nnewlines"
        );
        assert_eq!(
            first("A='dontexpand\\nnewlines'", "A"),
            "dontexpand\\nnewlines"
        );
        assert_eq!(first("I=`tick\\nvalue`", "I"), "tick\\nvalue");
        assert_eq!(first("T=\"a\\tb\\rc\"", "T"), "a\tb\rc");
        // Order quirk: `\\n` contains the substring `\n` → backslash + real LF.
        assert_eq!(first("V=\"\\\\n\"", "V"), "\\\n");
    }

    #[test]
    fn escape_expansion_can_be_disabled() {
        let opts = ScanOptions {
            expand_double_quoted_newlines: false,
            ..Default::default()
        };
        assert_eq!(scan("A=\"a\\nb\"", &opts).get("A").unwrap()[0], "a\\nb");
    }

    #[test]
    fn escaped_same_type_quotes_not_unescaped() {
        // Escaped same-type quotes keep their backslashes:
        // `M="say \"hi\""` → `say \"hi\"`.
        assert_eq!(first("M=\"say \\\"hi\\\"\"", "M"), "say \\\"hi\\\"");
    }

    #[test]
    fn bom_and_js_whitespace_absorbed() {
        // JS `\s` includes U+FEFF (BOM) and NBSP, so the LINE regex absorbs a
        // leading one.
        assert_eq!(first("\u{FEFF}KEY=v", "KEY"), "v");
        assert_eq!(first("\u{00A0}KEY=v", "KEY"), "v");
    }

    #[test]
    fn nel_is_not_js_whitespace() {
        // U+0085 is Unicode White_Space but outside JS `\s`, so a key preceded by
        // NEL on the same line is not at a line start and nothing parses.
        assert!(scan_default("A=1").contains_key("A"));
        assert!(!scan_default("\u{0085}A=1").contains_key("A"));
    }

    #[test]
    fn inner_different_quotes_preserved() {
        assert_eq!(
            first("A='double \"quotes\" work inside single quotes'", "A"),
            "double \"quotes\" work inside single quotes"
        );
        assert_eq!(
            first("B=`{\"foo\": \"bar's\"}`", "B"),
            "{\"foo\": \"bar's\"}"
        );
    }

    #[test]
    fn unquoted_values_trimmed_both_ends() {
        assert_eq!(first("D=  spaced   ", "D"), "spaced");
        assert_eq!(
            first("T=    some spaced out string", "T"),
            "some spaced out string"
        );
    }

    #[test]
    fn ik_ek_glob_filtering() {
        // ik selects, ek rejects, ek wins.
        let src = "CLOUD_KEY=1\nCLOUD_SECRET=2\nDB_URL=3";
        let ik = ScanOptions {
            ik: vec!["CLOUD_*".to_string()],
            ..Default::default()
        };
        let parsed = scan(src, &ik);
        assert_eq!(
            parsed.keys().collect::<Vec<_>>(),
            ["CLOUD_KEY", "CLOUD_SECRET"]
        );

        let ek = ScanOptions {
            ek: vec!["CLOUD_*".to_string()],
            ..Default::default()
        };
        let parsed = scan(src, &ek);
        assert_eq!(parsed.keys().collect::<Vec<_>>(), ["DB_URL"]);

        let both = ScanOptions {
            ik: vec!["CLOUD_*".to_string()],
            ek: vec!["CLOUD_SECRET".to_string()],
            ..Default::default()
        };
        let parsed = scan(src, &both);
        assert_eq!(parsed.keys().collect::<Vec<_>>(), ["CLOUD_KEY"]);
    }

    #[test]
    fn ik_ek_only_supports_literal_and_star_key_globs() {
        // Key filters intentionally support literals and `*`, not file-glob
        // extensions such as braces, negation, or extglobs.
        let src = "CLOUD_KEY=1\nCLOUD_SECRET=2\nDB_URL=3";
        let star = ScanOptions {
            ik: vec!["CLOUD_*".to_string()],
            ..Default::default()
        };
        assert_eq!(
            scan(src, &star).keys().collect::<Vec<_>>(),
            ["CLOUD_KEY", "CLOUD_SECRET"]
        );
    }

    #[test]
    #[should_panic(expected = "Key glob patterns must not be empty")]
    fn empty_ik_pattern_panics_like_the_js_throw() {
        // An empty glob panics through the infallible signature; callers
        // pre-validate via edit::KeyFilter::new.
        let opts = ScanOptions {
            ik: vec![String::new()],
            ..Default::default()
        };
        scan("A=1", &opts);
    }

    #[test]
    fn skipped_keys_never_reach_transform() {
        // A skipped key reaches neither `transform` nor `parsed`.
        let mut seen = Vec::new();
        let opts = ScanOptions {
            ek: vec!["AWS_*".to_string()],
            ..Default::default()
        };
        scan_with("AWS_KEY=1\nDB_URL=3", &opts, |e| {
            seen.push(e.name.to_string());
            e.value.to_string()
        });
        assert_eq!(seen, ["DB_URL"]);
    }

    #[test]
    fn transform_return_value_is_pushed() {
        let parsed = scan_with("A=1\nA=2", &ScanOptions::default(), |e| {
            format!("<{}>", e.value)
        });
        assert_eq!(
            parsed.get("A").unwrap(),
            &vec!["<1>".to_string(), "<2>".to_string()]
        );
    }

    #[test]
    fn spaced_key_and_value() {
        assert_eq!(first("    SPACED_KEY = parsed", "SPACED_KEY"), "parsed");
    }

    #[test]
    fn equals_signs_kept_in_value() {
        assert_eq!(first("EQUAL_SIGNS=equals==", "EQUAL_SIGNS"), "equals==");
    }

    #[test]
    fn tab_separator_around_equals() {
        assert_eq!(first("K\t=\tv", "K"), "v");
    }
}
