//! `filepaths(env_file)` — default and normalize the env-file list.
//!
//! Takes `None` (the `.env` default) or an explicit list. A single string and a
//! one-element list yield the same result, so the list is `Option<Vec<String>>`.

/// `filepaths(env_file = ".env")`: `None` → `[".env"]`; otherwise the list
/// as-provided.
pub fn filepaths(env_file: Option<Vec<String>>) -> Vec<String> {
  env_file.unwrap_or_else(|| vec![".env".to_string()])
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn defaults_to_dot_env() {
    assert_eq!(filepaths(None), vec![".env".to_string()]);
  }

  #[test]
  fn wraps_a_string() {
    assert_eq!(
      filepaths(Some(vec![".env.production".to_string()])),
      vec![".env.production".to_string()]
    );
  }

  #[test]
  fn returns_arrays_as_is() {
    let paths = vec![".env".to_string(), ".env.production".to_string()];
    assert_eq!(filepaths(Some(paths.clone())), paths);
  }
}
