//! `truncate`: shorten a value for display.
//!
//! `truncate(str, showChar = 7)`: when `str` is non-empty, return its first
//! `showChar` characters followed by `…` (U+2026); otherwise the empty string.
//! Used in every private-key error one-liner.

/// The horizontal-ellipsis appended to a truncated value (U+2026).
const ELLIPSIS: char = '…';

/// Default number of leading characters shown (`showChar = 7`).
const DEFAULT_SHOW_CHAR: usize = 7;

/// `truncate(value)` with the default `showChar = 7`.
///
/// `None`/empty → `""`; otherwise the first 7 chars + `…`.
pub fn truncate(value: Option<&str>) -> String {
    truncate_with(value, DEFAULT_SHOW_CHAR)
}

/// `truncate(value, show_char)`.
///
/// The JS `str.slice(0, showChar)` counts UTF-16 code units; every caller passes hex
/// key material (ASCII), so char-boundary slicing is byte-identical for real inputs.
pub fn truncate_with(value: Option<&str>, show_char: usize) -> String {
    match value {
        Some(s) if !s.is_empty() => {
            let visible: String = s.chars().take(show_char).collect();
            format!("{visible}{ELLIPSIS}")
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // tap: tests/lib/helpers/truncate.test.js:5-13
    fn truncate_default_seven_chars() {
        let private_key = "2c93601cba85b3b2474817897826ebef977415c097f0bf57dcbaa3056e5d64d0";
        assert_eq!(truncate(Some(private_key)), "2c93601…");
    }

    #[test]
    // tap: tests/lib/helpers/truncate.test.js:15-23
    fn truncate_eleven_chars() {
        let private_key = "dxo_123456789";
        assert_eq!(truncate_with(Some(private_key), 11), "dxo_1234567…");
    }

    #[test]
    // tap: tests/lib/helpers/truncate.test.js:25-33
    fn truncate_null_private_key() {
        assert_eq!(truncate(None), "");
        // JS also treats the empty string as falsy (`str && str.length > 0`).
        assert_eq!(truncate(Some("")), "");
    }
}
