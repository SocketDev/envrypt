#![no_main]
//! FUZZ target `upsert_roundtrip` (WP-21, doc 11 §7.2 target 3).
//!
//! `arbitrary`-derived `(src, key, value)` (src size-capped; key constrained to
//! the KEY charset; value constrained to a "clean" charset so the parity
//! properties below are well-defined — see the note on value constraints). Three
//! properties, all JS-parity (`edit::upsert`, doc 02 §9.1):
//!
//! (a) NEVER PANICS on ANY input (a fancy-regex engine error degrades to no-match,
//!     D-10) — the PRIMARY property (doc 11 §7.2: "Finding = panic");
//! (b) DETERMINISM — `upsert` is pure: a second call on the same input is
//!     byte-identical;
//! (c) scan-back + scan-back-idempotence, GUARDED to a CLEAN src (only `KEY=value`
//!     lines): `collapse(scan_raw(upsert(src,k,v)))[k] == v`, ditto after a second
//!     upsert.
//!
//! Why (c) is guarded: over arbitrary/malformed src, `scan(upsert(src,k,v))[k] == v`
//! is NOT a universal invariant — there is a long tail of parity-preserving scan
//! interactions where it fails in BOTH engines (all verified against the upstream
//! reference `primitives` 1.8.1): key absent → appended line absorbed by an earlier
//! open quote (`scan("…\nDencred:\nK=\"a\"")` has no `K`); empty scanned value +
//! trailing `#` comment (`upsert("K=# ",…)` is a no-op); an empty rewrite
//! unshadowing a following quote. doc 11 §7.2's idealized "byte-idempotence" (c)
//! is likewise not an invariant (a src carrying a literal `\0ENVRYPT_UPSERT_0\0`
//! collides on pass 2 in both engines). So (c) asserts the semantic postcondition
//! only where it is provably robust, while (a) fuzzes the entire space for
//! panics. The `\0ENVRYPT_UPSERT_i\0` placeholder-collision behavior is
//! additionally pinned by the `edit::upsert` placeholder-collision unit test
//! (byte-non-idempotent in BOTH engines).
//!
//! Value-constraint rationale: the value is restricted to a clean charset (no
//! quotes/newline/`#`/`$`/NUL) so it round-trips through scan unambiguously wherever
//! (c) fires; the SRC (the interesting fuzz surface) stays fully arbitrary and (a)
//! exercises all of it.

use arbitrary::Arbitrary;
use envrypt::edit::{upsert, UpsertValue};
use envrypt::parse::{scan, ScanOptions};
use libfuzzer_sys::fuzz_target;

/// Cap the src so upsert's O(occurrences × len) worst case stays bounded (doc 11
/// §4 WP-04 pathology note: the fuzz target bounds input size).
const MAX_SRC_BYTES: usize = 4096;
const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 256;

#[derive(Arbitrary, Debug)]
struct Input {
    src: String,
    key: String,
    value: String,
}

/// A KEY the scan tokenizer always recognizes: `[A-Za-z_][A-Za-z0-9_]*`. Any
/// out-of-charset byte is dropped; a leading digit gets a `K` prepended; an empty
/// result is rejected by the caller.
fn sanitize_key(raw: &str) -> String {
    let mut out = String::new();
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        }
        if out.len() >= MAX_KEY_BYTES {
            break;
        }
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, 'K');
        out.truncate(MAX_KEY_BYTES);
    }
    out
}

/// A "clean" value whose scan-back is unambiguous: ASCII alnum plus a small set of
/// safe symbols — no whitespace, quotes/backtick, `#`, `$`, `=`, or NUL, which
/// could change quoting/comment/line/expand interpretation on re-scan. May be
/// empty (exercises the blank-value branch).
fn sanitize_value(raw: &str) -> String {
    let mut out = String::new();
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '@' | '+') {
            out.push(c);
        }
        if out.len() >= MAX_VALUE_BYTES {
            break;
        }
    }
    out
}

/// Truncate to a char boundary at or below `max` bytes.
fn cap(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

/// Raw scan options (doc 02 §9.1) — exactly what `upsert` scans with internally.
fn raw_scan_options() -> ScanOptions {
    ScanOptions {
        convert_windows_newlines: false,
        expand_double_quoted_newlines: false,
        ..Default::default()
    }
}

fn scan_key_last(s: &str, key: &str) -> Option<String> {
    scan(s, &raw_scan_options())
        .get(key)
        .and_then(|occurrences| occurrences.last())
        .cloned()
}

/// True iff `c` is a safe unquoted-value byte (no whitespace/quote/`#`/`$`/`=`/NUL
/// so no comment/quote/expand/absorption interaction on scan).
fn is_value_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'+')
}

/// A src over which scan-back is a PROVABLY robust invariant: every line is either
/// empty or a strict `IDENT=value` assignment (`IDENT` = `[A-Za-z_][A-Za-z0-9_]*`,
/// value = [`is_value_byte`]s). This excludes every construct that makes scan-back
/// diverge from the upserted value in a JS-parity way — a KEYLESS line whose value
/// absorbs the next line (`encrypted:\nX=1` → scan key "encrypted", no X — verified
/// in the upstream reference `primitives` 1.8.1), quotes/backtick, `#` comments,
/// whitespace trim, CRLF, NUL, `$`/`{}` expansion. On such a src both engines
/// round-trip; over arbitrary src they do not (all exceptions reference-verified).
fn is_clean_src(src: &str) -> bool {
    src.split('\n').all(|line| {
        if line.is_empty() {
            return true;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false; // keyless line — can absorb following content
        };
        let mut kb = key.bytes();
        matches!(kb.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
            && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && value.bytes().all(is_value_byte)
    })
}

fuzz_target!(|input: Input| {
    let key = sanitize_key(&input.key);
    if key.is_empty() {
        return;
    }
    let value = cap(sanitize_value(&input.value), MAX_VALUE_BYTES);
    let src = cap(input.src, MAX_SRC_BYTES);

    // (a) NEVER PANICS on any input — the PRIMARY property (doc 11 §7.2 target 3:
    // "Finding = panic/abort/overflow/OOM/hang"). Covers every fuzz input, incl.
    // malformed/CRLF/BOM/NUL/placeholder-collision sources.
    let once = upsert(&src, &key, UpsertValue::Single(&value)).into_owned();

    // (b) DETERMINISM — `upsert` is a pure function: a second call on the SAME
    // input is byte-identical (no RNG, no global state, IndexMap-ordered).
    let again = upsert(&src, &key, UpsertValue::Single(&value)).into_owned();
    assert_eq!(again, once, "upsert must be deterministic\n key={key:?}\n src={src:?}");

    // (c) scan-back + scan-back-idempotence, GUARDED to a CLEAN src (only KEY=value
    // lines). Over arbitrary/malformed src, `scan(upsert(src,k,v))[k] == v` is NOT
    // a universal invariant — there is a long tail of parity-preserving scan
    // interactions where it fails in BOTH engines (append absorbed by an open
    // quote; empty scanned value + `#` comment; empty rewrite unshadowing a
    // following quote — all reference-verified). Here we assert the semantic
    // postcondition only where it is provably robust, while (a) fuzzes the whole
    // space for panics.
    if is_clean_src(&src) {
        assert_eq!(
            scan_key_last(&once, &key).as_deref(),
            Some(value.as_str()),
            "clean-src scan-back of upsert(src,k,v)[k] must equal v\n key={key:?}\n \
             value={value:?}\n src={src:?}\n out={once:?}"
        );
        let twice = upsert(&once, &key, UpsertValue::Single(&value)).into_owned();
        assert_eq!(
            scan_key_last(&twice, &key).as_deref(),
            Some(value.as_str()),
            "clean-src scan-back of upsert(upsert(src,k,v),k,v)[k] must still equal v\n \
             key={key:?}\n value={value:?}\n src={src:?}\n twice={twice:?}"
        );
    }
});
