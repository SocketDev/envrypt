//! `environment(filepath)` — filename → environment name.

use super::canonical::canonical_env_filename;

/// `.env` → `development`; `.env.production` → `production`;
/// `.env.development.local` → `development_local`; `.env.some.other.thing` →
/// `some_other` (first two extra segments); `.env1` → `development1`;
/// `secrets.txt` → `secrets.txt` (passthrough).
pub fn environment(filepath: &str) -> String {
  let filename = canonical_env_filename(filepath);

  let parts: Vec<&str> = filename.split('.').collect();
  // The segments after the leading empty part and `env`.
  let possible: &[&str] = if parts.len() > 2 { &parts[2..] } else { &[] };

  match possible.len() {
    // `.env1` → `development1`, `.env` → `development`, non-dotenv names pass
    // through (replace only the FIRST `.env`).
    0 => filename.replacen(".env", "development", 1),
    1 => possible[0].to_string(),
    2 => possible.join("_"),
    _ => possible[..2].join("_"),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn dot_env_is_development() {
    assert_eq!(environment(".env"), "development");
  }

  #[test]
  fn dot_env_production() {
    assert_eq!(environment(".env.production"), "production");
  }

  #[test]
  fn dot_env_txt_is_development() {
    assert_eq!(environment(".env.txt"), "development");
  }

  #[test]
  fn dot_env_production_txt() {
    assert_eq!(environment(".env.production.txt"), "production");
  }

  #[test]
  fn uppercase_dot_env_production() {
    assert_eq!(environment(".ENV.PRODUCTION"), "production");
  }

  #[test]
  fn dot_env_local() {
    assert_eq!(environment(".env.local"), "local");
  }

  #[test]
  fn dot_env_development_local() {
    assert_eq!(environment(".env.development.local"), "development_local");
  }

  #[test]
  fn dot_env_development_production() {
    assert_eq!(
      environment(".env.development.production"),
      "development_production"
    );
  }

  #[test]
  fn dot_env_some_other_thing_truncates_to_two() {
    assert_eq!(environment(".env.some.other.thing"), "some_other");
  }

  #[test]
  fn dot_env1_is_development1() {
    assert_eq!(environment(".env1"), "development1");
  }

  #[test]
  fn non_dotenv_name_passes_through() {
    assert_eq!(environment("secrets.txt"), "secrets.txt");
  }
}
