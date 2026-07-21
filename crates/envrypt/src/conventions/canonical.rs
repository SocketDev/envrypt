//! `canonical_env_filename(filepath)`.
//!
//! The lower-cased basename, with a trailing `.txt` stripped ONLY when the
//! lowered name both starts with `.env` and ends with `.txt`.

use std::path::Path;

/// `canonicalEnvFilename(filepath)` — lower-cased basename; strips a trailing
/// `.txt` when the (lowered) name starts with `.env` and ends with `.txt`.
///
/// `.env.production.txt` → `.env.production`; `.ENV.LOCAL.TXT` → `.env.local`;
/// `secrets.txt` → `secrets.txt` (not `.env`-prefixed, so kept verbatim).
pub fn canonical_env_filename(filepath: &str) -> String {
  // The last path component. `Path::file_name` returns `None` for `.`/`..`/`/`;
  // those are not env filenames, so fall back to the whole input.
  let basename = Path::new(filepath)
    .file_name()
    .and_then(|s| s.to_str())
    .unwrap_or(filepath);

  let mut filename = basename.to_lowercase();

  if filename.starts_with(".env") && filename.ends_with(".txt") {
    // Drop the 4-char `.txt` suffix.
    filename.truncate(filename.len() - 4);
  }

  filename
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn dot_env() {
    assert_eq!(canonical_env_filename(".env"), ".env");
  }

  #[test]
  fn dot_env_txt() {
    assert_eq!(canonical_env_filename(".env.txt"), ".env");
  }

  #[test]
  fn dot_env_production_txt() {
    assert_eq!(
      canonical_env_filename(".env.production.txt"),
      ".env.production"
    );
  }

  #[test]
  fn uppercase_dot_env_local_txt() {
    assert_eq!(canonical_env_filename(".ENV.LOCAL.TXT"), ".env.local");
  }

  #[test]
  fn secrets_txt_unchanged() {
    assert_eq!(canonical_env_filename("secrets.txt"), "secrets.txt");
  }

  // A directory-qualified path takes only its basename.
  #[test]
  fn strips_directory_component() {
    assert_eq!(
      canonical_env_filename("/some/dir/.env.PRODUCTION.txt"),
      ".env.production"
    );
  }
}
