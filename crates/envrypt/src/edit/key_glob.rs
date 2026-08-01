//! Small glob matcher for environment-variable key names.
//!
//! Envrypt supports literal patterns plus `*`, which matches zero or more
//! characters. It deliberately does not implement file-path globbing,
//! JavaScript regex syntax, or file-glob extensions.

use std::fmt;

const MAX_PATTERN_LENGTH: usize = 64 * 1024;

/// A rejected key-glob pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchError {
  /// Patterns select at least one named key.
  EmptyPattern,
  /// A bounded pattern prevents untrusted CLI input from allocating freely.
  InputTooLong { length: usize, max: usize },
  /// The key-filter language only reserves `*` as a wildcard.
  UnsupportedSyntax { character: char },
}

impl fmt::Display for MatchError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      MatchError::EmptyPattern => f.write_str("Key glob patterns must not be empty"),
      MatchError::InputTooLong { length, max } => {
        write!(f, "Key glob length {length} exceeds the {max}-byte limit")
      }
      MatchError::UnsupportedSyntax { character } => write!(
        f,
        "Unsupported key glob syntax {character:?}; only * is a wildcard"
      ),
    }
  }
}

impl std::error::Error for MatchError {}

/// Compiled literal-or-`*` key patterns.
#[derive(Debug)]
pub struct Matcher {
  patterns: Vec<String>,
}

/// Builds a matcher for the supported key-glob language.
pub fn matcher(patterns: &[String]) -> Result<Matcher, MatchError> {
  for pattern in patterns {
    validate(pattern)?;
  }
  Ok(Matcher {
    patterns: patterns.to_vec(),
  })
}

impl Matcher {
  /// Returns true when any pattern matches a non-empty key name.
  pub fn is_match(&self, input: &str) -> bool {
    !input.is_empty() && self.patterns.iter().any(|pattern| matches(pattern, input))
  }
}

fn validate(pattern: &str) -> Result<(), MatchError> {
  if pattern.is_empty() {
    return Err(MatchError::EmptyPattern);
  }
  if pattern.len() > MAX_PATTERN_LENGTH {
    return Err(MatchError::InputTooLong {
      length: pattern.len(),
      max: MAX_PATTERN_LENGTH,
    });
  }
  if let Some(character) = pattern.chars().find(|character| {
    matches!(
      character,
      '?' | '[' | ']' | '{' | '}' | '(' | ')' | '!' | '\\'
    )
  }) {
    return Err(MatchError::UnsupportedSyntax { character });
  }
  Ok(())
}

fn matches(pattern: &str, input: &str) -> bool {
  if !pattern.contains('*') {
    return pattern == input;
  }

  let parts: Vec<&str> = pattern.split('*').collect();
  let first = parts[0];
  if !input.starts_with(first) {
    return false;
  }
  let mut rest = &input[first.len()..];

  let last_index = parts.len() - 1;
  for part in &parts[1..last_index] {
    if part.is_empty() {
      continue;
    }
    let Some(index) = rest.find(part) else {
      return false;
    };
    rest = &rest[index + part.len()..];
  }

  let last = parts[last_index];
  last.is_empty() || rest.ends_with(last)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn matcher_for(patterns: &[&str]) -> Matcher {
    matcher(
      &patterns
        .iter()
        .map(|pattern| (*pattern).to_string())
        .collect::<Vec<_>>(),
    )
    .unwrap()
  }

  #[test]
  fn matches_literals_and_star_globs() {
    let matcher = matcher_for(&["DATABASE_URL", "NEXT_PUBLIC_*", "*_PLAIN", "A_*_Z"]);
    for key in ["DATABASE_URL", "NEXT_PUBLIC_TOKEN", "NAME_PLAIN", "A_MID_Z"] {
      assert!(matcher.is_match(key), "{key}");
    }
    for key in ["DATABASE", "NEXT_PRIVATE_TOKEN", "PLAIN", "A_Z", ""] {
      assert!(!matcher.is_match(key), "{key}");
    }
  }

  #[test]
  fn rejects_unsupported_glob_syntax() {
    for character in ['?', '[', ']', '{', '}', '(', ')', '!', '\\'] {
      assert_eq!(
        matcher(&[format!("KEY{character}")]).unwrap_err(),
        MatchError::UnsupportedSyntax { character }
      );
    }
  }

  #[test]
  fn rejects_empty_and_overlong_patterns() {
    assert_eq!(
      matcher(&[String::new()]).unwrap_err(),
      MatchError::EmptyPattern
    );
    let pattern = "A".repeat(MAX_PATTERN_LENGTH + 1);
    assert_eq!(
      matcher(&[pattern]).unwrap_err(),
      MatchError::InputTooLong {
        length: MAX_PATTERN_LENGTH + 1,
        max: MAX_PATTERN_LENGTH,
      }
    );
  }
}
