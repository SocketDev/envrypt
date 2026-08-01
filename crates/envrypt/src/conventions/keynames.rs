//! `keynames(filepath, src)` → the public/private key NAMES for a file.
//!
//! The key-identifier NAMES are **configurable** and default to the `ENVRYPT_`
//! family. A consumer may opt into `DOTENV_` via [`KeyNaming::from_prefix`].
//! Resolution order:
//! 1. `scan(src)`; the FIRST key starting with the configured public-key prefix
//!    wins, and the private name is derived by replacing `<PREFIX>PUBLIC_KEY` with
//!    `<PREFIX>PRIVATE_KEY` (an in-file header overrides filename-derived naming).
//! 2. Else from the canonical filename: exactly `.env` → the base names (or the
//!    explicit `public_key_var`/`private_key_var` overrides).
//! 3. Else `<PREFIX>PUBLIC_KEY_<ENV>` / `<PREFIX>PRIVATE_KEY_<ENV>` where
//!    `<ENV> = environment(filename)` upper-cased.

use super::canonical::canonical_env_filename;
use super::environment::environment;
use crate::parse::{scan, ScanOptions};

/// The default key-identifier prefix: drives both `ENVRYPT_PUBLIC_KEY[_<ENV>]`
/// and `ENVRYPT_PRIVATE_KEY[_<ENV>]`.
pub const DEFAULT_KEY_PREFIX: &str = "ENVRYPT_";

/// Configurable key-identifier naming. A `prefix` (default `ENVRYPT_`) drives the
/// `<PREFIX>PUBLIC_KEY`/`<PREFIX>PRIVATE_KEY` families; explicit
/// `public_key_var`/`private_key_var` override the exact variable names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyNaming {
  /// The public-key family prefix, e.g. `ENVRYPT_PUBLIC_KEY`.
  pub public_key_prefix: String,
  /// The private-key family prefix, e.g. `ENVRYPT_PRIVATE_KEY`.
  pub private_key_prefix: String,
  /// An explicit public-key variable name override (wins over the prefix).
  pub public_key_var: Option<String>,
  /// An explicit private-key variable name override (wins over the prefix).
  pub private_key_var: Option<String>,
}

impl Default for KeyNaming {
  fn default() -> Self {
    Self::from_prefix(DEFAULT_KEY_PREFIX)
  }
}

impl KeyNaming {
  /// Build a naming from a bare prefix (default `ENVRYPT_` →
  /// `ENVRYPT_PUBLIC_KEY` / `ENVRYPT_PRIVATE_KEY`). Pass `from_prefix("DOTENV_")`
  /// for the `DOTENV_` family.
  pub fn from_prefix(prefix: &str) -> Self {
    Self {
      public_key_prefix: format!("{prefix}PUBLIC_KEY"),
      private_key_prefix: format!("{prefix}PRIVATE_KEY"),
      public_key_var: None,
      private_key_var: None,
    }
  }

  /// Whether `name` names a private key under this config (family-prefix match OR
  /// the explicit `private_key_var`).
  pub fn is_private_key_name(&self, name: &str) -> bool {
    name.starts_with(&self.private_key_prefix) || self.private_key_var.as_deref() == Some(name)
  }

  /// Whether `name` names a public key under this config.
  pub fn is_public_key_name(&self, name: &str) -> bool {
    name.starts_with(&self.public_key_prefix) || self.public_key_var.as_deref() == Some(name)
  }

  /// The base (`.env`) public key name — the explicit override wins.
  pub fn base_public(&self) -> String {
    self
      .public_key_var
      .clone()
      .unwrap_or_else(|| self.public_key_prefix.clone())
  }

  /// The base (`.env`) private key name — the explicit override wins.
  pub fn base_private(&self) -> String {
    self
      .private_key_var
      .clone()
      .unwrap_or_else(|| self.private_key_prefix.clone())
  }
}

/// A shared default (`ENVRYPT_`) naming for the zero-config path.
pub fn default_key_naming() -> &'static KeyNaming {
  static DEFAULT: std::sync::LazyLock<KeyNaming> = std::sync::LazyLock::new(KeyNaming::default);
  &DEFAULT
}

/// Public + private key variable names for a given env file / source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyNames {
  pub public_key_name: String,
  pub private_key_name: String,
}

/// `keynames(filepath, src)` with the default `ENVRYPT_` naming. Pass `src = ""`
/// to derive purely from the filename.
pub fn keynames(filepath: &str, src: &str) -> KeyNames {
  keynames_with(filepath, src, default_key_naming())
}

/// `keynames(filepath, src)` under an explicit [`KeyNaming`].
pub fn keynames_with(filepath: &str, src: &str, naming: &KeyNaming) -> KeyNames {
  // (1) An in-file `<PREFIX>PUBLIC_KEY*` header wins. `scan` preserves
  // first-appearance key order, so the first matching key is the header.
  let scanned = scan(src, &ScanOptions::default());
  for public_key_name in scanned.keys() {
    if public_key_name.starts_with(&naming.public_key_prefix) {
      return KeyNames {
        public_key_name: public_key_name.clone(),
        private_key_name: public_key_name.replacen(
          &naming.public_key_prefix,
          &naming.private_key_prefix,
          1,
        ),
      };
    }
  }

  let filename = canonical_env_filename(filepath);

  // (2) exactly `.env` → base names (explicit var overrides win).
  if filename == ".env" {
    return KeyNames {
      public_key_name: naming.base_public(),
      private_key_name: naming.base_private(),
    };
  }

  // (3) `.env.<ENVIRONMENT>` → suffixed names.
  let resolved = environment(&filename).to_uppercase();
  KeyNames {
    public_key_name: format!("{}_{resolved}", naming.public_key_prefix),
    private_key_name: format!("{}_{resolved}", naming.private_key_prefix),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn names(filepath: &str) -> KeyNames {
    keynames(filepath, "")
  }

  #[test]
  fn base_key_names_for_dot_env() {
    assert_eq!(
      names(".env"),
      KeyNames {
        public_key_name: "ENVRYPT_PUBLIC_KEY".into(),
        private_key_name: "ENVRYPT_PRIVATE_KEY".into(),
      }
    );
  }

  #[test]
  fn environment_key_names_for_production() {
    assert_eq!(
      names(".env.production"),
      KeyNames {
        public_key_name: "ENVRYPT_PUBLIC_KEY_PRODUCTION".into(),
        private_key_name: "ENVRYPT_PRIVATE_KEY_PRODUCTION".into(),
      }
    );
  }

  #[test]
  fn local_environment_key_names() {
    assert_eq!(
      names(".env.ci.local"),
      KeyNames {
        public_key_name: "ENVRYPT_PUBLIC_KEY_CI_LOCAL".into(),
        private_key_name: "ENVRYPT_PRIVATE_KEY_CI_LOCAL".into(),
      }
    );
  }

  #[test]
  fn handles_dot_env1() {
    assert_eq!(
      names(".env1"),
      KeyNames {
        public_key_name: "ENVRYPT_PUBLIC_KEY_DEVELOPMENT1".into(),
        private_key_name: "ENVRYPT_PRIVATE_KEY_DEVELOPMENT1".into(),
      }
    );
  }

  #[test]
  fn truncates_long_environment_suffixes() {
    assert_eq!(
      names(".env.ci.local.extra"),
      KeyNames {
        public_key_name: "ENVRYPT_PUBLIC_KEY_CI_LOCAL".into(),
        private_key_name: "ENVRYPT_PRIVATE_KEY_CI_LOCAL".into(),
      }
    );
  }

  #[test]
  fn handles_dot_env_txt() {
    assert_eq!(
      names(".env.txt"),
      KeyNames {
        public_key_name: "ENVRYPT_PUBLIC_KEY".into(),
        private_key_name: "ENVRYPT_PRIVATE_KEY".into(),
      }
    );
  }

  #[test]
  fn handles_dot_env_production_txt() {
    assert_eq!(
      names(".env.production.txt"),
      KeyNames {
        public_key_name: "ENVRYPT_PUBLIC_KEY_PRODUCTION".into(),
        private_key_name: "ENVRYPT_PRIVATE_KEY_PRODUCTION".into(),
      }
    );
  }

  #[test]
  fn handles_uppercase_filenames() {
    assert_eq!(
      names(".ENV.LOCAL"),
      KeyNames {
        public_key_name: "ENVRYPT_PUBLIC_KEY_LOCAL".into(),
        private_key_name: "ENVRYPT_PRIVATE_KEY_LOCAL".into(),
      }
    );
  }

  // An in-file ENVRYPT_PUBLIC_KEY* header overrides filename-derived naming.
  // Pins the src-driven branch.
  #[test]
  fn in_file_public_key_header_wins() {
    assert_eq!(
      keynames(".env.production", "ENVRYPT_PUBLIC_KEY_STAGING=\"abc\""),
      KeyNames {
        public_key_name: "ENVRYPT_PUBLIC_KEY_STAGING".into(),
        private_key_name: "ENVRYPT_PRIVATE_KEY_STAGING".into(),
      }
    );
  }
}
