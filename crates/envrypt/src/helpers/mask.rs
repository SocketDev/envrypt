//! Redacts a secret for safe display in logs and diagnostics.
//!
//! Reveals the first two characters of a value and replaces every remaining
//! character with a fixed mask character (`*`). A value of three characters or
//! fewer is masked in full — too short to reveal a prefix without leaking most
//! of the secret — and an empty value yields `""`. The masked output always has
//! the same character count as the input, so it never hints at a longer or
//! shorter secret than the original.

/// The string each redacted character position is replaced with.
const MASK: &str = "*";

/// The number of leading characters revealed on a value long enough to keep a
/// prefix (four characters or more).
const REVEAL: usize = 2;

/// Returns a redacted form of `value`: its first `REVEAL` characters followed by
/// one `MASK` for every remaining character. A value of three characters or
/// fewer is masked in full, and an empty value yields `""`.
pub fn mask(value: &str) -> String {
  let len = value.chars().count();
  // Three characters or fewer (an empty value included) can't keep a prefix
  // without leaking most of the value, so redact every position.
  if len <= REVEAL + 1 {
    return MASK.repeat(len);
  }
  let prefix: String = value.chars().take(REVEAL).collect();
  format!("{prefix}{}", MASK.repeat(len - REVEAL))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn masks_a_normal_value_keeping_a_short_prefix() {
    assert_eq!(mask("abcd"), "ab**");
    let masked = mask("s3cr3t-value");
    assert_eq!(masked.chars().count(), "s3cr3t-value".chars().count());
    assert!(masked.starts_with("s3"));
    assert!(masked[2..].chars().all(|c| c == '*'));
  }

  #[test]
  fn fully_masks_a_short_value() {
    assert_eq!(mask("a"), "*");
    assert_eq!(mask("ab"), "**");
    assert_eq!(mask("abc"), "***");
  }

  #[test]
  fn empty_value_yields_empty_string() {
    assert_eq!(mask(""), "");
  }
}
