//! `--convention nextjs|flow` preset file lists.
//!
//! `convention_filepaths(convention, env)` returns the ordered env-file list for a
//! preset. The env NAME is injected by the caller, resolved from its env map (see
//! `resolvers::envs::conventions_env_name`, which reads
//! `DOTENV_ENV || NODE_ENV || 'development'`).

use crate::errors::EnvryptError;

/// The ordered env-file list for `convention`, or an `INVALID_CONVENTION` error
/// for an unknown name.
pub fn convention_filepaths(convention: &str, env: &str) -> Result<Vec<String>, EnvryptError> {
  match convention {
    "nextjs" => {
      // A canonical env is one of development/test/production. A
      // non-canonical env drops BOTH `.env.<env>.local` and `.env.<env>` but
      // keeps `.env.local` and `.env`.
      let canonical = matches!(env, "development" | "test" | "production");
      let mut out = Vec::new();
      if canonical {
        out.push(format!(".env.{env}.local"));
      }
      if !(canonical && env == "test") {
        out.push(".env.local".to_string());
      }
      if canonical {
        out.push(format!(".env.{env}"));
      }
      out.push(".env".to_string());
      Ok(out)
    }
    "flow" => Ok(vec![
      format!(".env.{env}.local"),
      format!(".env.{env}"),
      ".env.local".to_string(),
      ".env".to_string(),
      ".env.defaults".to_string(),
    ]),
    other => Err(EnvryptError::invalid_convention(other)),
  }
}

#[cfg(test)]
mod tests {
  // The `conventions` helper below composes name-resolution and list-building:
  // `conventions_env_name(map)` resolves the env name from an injected env map,
  // then `convention_filepaths(name, env)` builds the ordered list. A subtest
  // that sets nothing resolves to `development`.
  use super::*;
  use crate::resolvers::envs::conventions_env_name;
  use indexmap::IndexMap;

  /// Compose name-resolution and list-building over an injected env map (the
  /// subtest's own `NODE_ENV`/`DOTENV_ENV`, if any).
  fn conventions(
    convention: &str,
    env_pairs: &[(&str, &str)],
  ) -> Result<Vec<String>, EnvryptError> {
    let map: IndexMap<String, String> = env_pairs
      .iter()
      .map(|(k, v)| (k.to_string(), v.to_string()))
      .collect();
    convention_filepaths(convention, &conventions_env_name(&map))
  }

  #[test]
  fn nextjs_default_development() {
    assert_eq!(
      conventions("nextjs", &[]).unwrap(),
      vec![
        ".env.development.local",
        ".env.local",
        ".env.development",
        ".env"
      ]
    );
  }

  #[test]
  fn flow_default_development() {
    assert_eq!(
      conventions("flow", &[]).unwrap(),
      vec![
        ".env.development.local",
        ".env.development",
        ".env.local",
        ".env",
        ".env.defaults"
      ]
    );
  }

  #[test]
  fn invalid_convention_message_code_help() {
    let err = conventions("invalid", &[]).unwrap_err();
    assert_eq!(
      err.message(),
      "[INVALID_CONVENTION] invalid convention (invalid)"
    );
    assert_eq!(err.code(), Some("INVALID_CONVENTION"));
    assert_eq!(
      err.help(),
      Some("fix: [https://github.com/SocketDev/envrypt/issues/761]")
    );
  }

  #[test]
  fn nextjs_node_env_test_skips_env_local() {
    assert_eq!(
      conventions("nextjs", &[("NODE_ENV", "test")]).unwrap(),
      vec![".env.test.local", ".env.test", ".env"]
    );
  }

  #[test]
  fn nextjs_dotenv_env_test_skips_env_local() {
    assert_eq!(
      conventions("nextjs", &[("DOTENV_ENV", "test")]).unwrap(),
      vec![".env.test.local", ".env.test", ".env"]
    );
  }

  #[test]
  fn flow_node_env_test() {
    assert_eq!(
      conventions("flow", &[("NODE_ENV", "test")]).unwrap(),
      vec![
        ".env.test.local",
        ".env.test",
        ".env.local",
        ".env",
        ".env.defaults"
      ]
    );
  }

  #[test]
  fn nextjs_unrecognized_env_keeps_env_local() {
    assert_eq!(
      conventions("nextjs", &[("NODE_ENV", "unrecognized")]).unwrap(),
      vec![".env.local", ".env"]
    );
  }

  #[test]
  fn flow_unrecognized_env_uses_raw_name() {
    assert_eq!(
      conventions("flow", &[("NODE_ENV", "unrecognized")]).unwrap(),
      vec![
        ".env.unrecognized.local",
        ".env.unrecognized",
        ".env.local",
        ".env",
        ".env.defaults"
      ]
    );
  }

  // `DOTENV_ENV` beats `NODE_ENV` for the resolved env name.
  #[test]
  fn dotenv_env_beats_node_env() {
    assert_eq!(
      conventions(
        "nextjs",
        &[("DOTENV_ENV", "test"), ("NODE_ENV", "production")]
      )
      .unwrap(),
      vec![".env.test.local", ".env.test", ".env"]
    );
  }
}
