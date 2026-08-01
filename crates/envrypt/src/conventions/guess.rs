//! `guess_private_key_filename(private_key_name)`, the inverse of `keynames`.
//!
//! Maps a `<PREFIX>PRIVATE_KEY[_ENV…]` env-var NAME back to the `.env[.env…]` file
//! it belongs to, picking default env files from the private-key names in the
//! process env. The prefix is configurable and defaults to `ENVRYPT_PRIVATE_KEY`.

use crate::conventions::keynames::{default_key_naming, KeyNaming};

/// `ENVRYPT_PRIVATE_KEY` → `.env`; `ENVRYPT_PRIVATE_KEY_PRODUCTION` → `.env.production`
/// under the default naming. See [`guess_private_key_filename_with`].
pub fn guess_private_key_filename(private_key_name: &str) -> String {
  guess_private_key_filename_with(private_key_name, default_key_naming())
}

/// Map a private-key variable NAME back to its `.env` filename under an explicit
/// [`KeyNaming`]: `<prefix>PRIVATE_KEY` → `.env`; `<prefix>PRIVATE_KEY_PRODUCTION`
/// → `.env.production`; `..._DEVELOPMENT_LOCAL_ME` → `.env.development.local.me`.
pub fn guess_private_key_filename_with(private_key_name: &str, naming: &KeyNaming) -> String {
  let prefix = &naming.private_key_prefix;
  if private_key_name == prefix {
    return ".env".to_string();
  }

  // Drop `${prefix}_` and turn the remaining `_`-segments into dotted, lowercase
  // filename parts. `.chars().skip(..)` is char-boundary-safe.
  let prefix_underscore_len = prefix.chars().count() + 1;
  let suffix: String = private_key_name
    .chars()
    .skip(prefix_underscore_len)
    .collect();
  let dotted = suffix
    .split('_')
    .collect::<Vec<&str>>()
    .join(".")
    .to_lowercase();

  format!(".env.{dotted}")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn base_private_key() {
    assert_eq!(guess_private_key_filename("ENVRYPT_PRIVATE_KEY"), ".env");
  }

  #[test]
  fn production() {
    assert_eq!(
      guess_private_key_filename("ENVRYPT_PRIVATE_KEY_PRODUCTION"),
      ".env.production"
    );
  }

  #[test]
  fn ci() {
    assert_eq!(
      guess_private_key_filename("ENVRYPT_PRIVATE_KEY_CI"),
      ".env.ci"
    );
  }

  #[test]
  fn development_local() {
    assert_eq!(
      guess_private_key_filename("ENVRYPT_PRIVATE_KEY_DEVELOPMENT_LOCAL"),
      ".env.development.local"
    );
  }

  #[test]
  fn development_local_me() {
    assert_eq!(
      guess_private_key_filename("ENVRYPT_PRIVATE_KEY_DEVELOPMENT_LOCAL_ME"),
      ".env.development.local.me"
    );
  }
}
