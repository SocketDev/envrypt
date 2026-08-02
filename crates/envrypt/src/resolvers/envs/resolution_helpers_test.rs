// Pins for default selection, file-path preparation, and lexical paths.
use super::test_helpers::*;
use super::*;

#[test]
fn determine_defaults_to_dotenv_file() {
    let pe = env_map(&[]);
    assert_eq!(determine(vec![], &pe, &KeyNaming::default()), vec![".env"]);
}

#[test]
fn determine_guesses_filenames_from_private_key_names() {
    // ENVRYPT_PRIVATE_KEY_X_Y → .env.x.y (underscores → dots, lowercased);
    // multiple keys → multiple defaults, in env order.
    let pe = env_map(&[
        ("ENVRYPT_PRIVATE_KEY_PRODUCTION", "abc"),
        ("ENVRYPT_PRIVATE_KEY", "def"),
    ]);
    assert_eq!(
        determine(vec![], &pe, &KeyNaming::default()),
        vec![".env.production", ".env",]
    );
}

#[test]
fn determine_returns_paths_unchanged_when_a_file_is_specified() {
    let pe = env_map(&[("ENVRYPT_PRIVATE_KEY", "abc")]);
    let paths = vec![".env.custom".to_string()];
    assert_eq!(determine(paths.clone(), &pe, &KeyNaming::default()), paths);
}

#[test]
fn build_env_file_paths_prepends_convention_files() {
    // Conventions first, then explicit file paths.
    let global = env_map(&[]);
    let cwd = std::env::temp_dir();
    let out = build_env_file_paths(&[".env2".to_string()], Some("flow"), &global, &cwd).unwrap();
    assert_eq!(
        out,
        vec![
            ".env.development.local",
            ".env.development",
            ".env.local",
            ".env",
            ".env.defaults",
            ".env2",
        ]
    );
}

#[test]
fn build_env_file_paths_resolves_directory_to_dotenv() {
    // An existing directory becomes `<dir>/.env` in its original relative
    // form (banner: `⟐ injected env (1) from sub/.env`).
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let global = env_map(&[]);
    let out = build_env_file_paths(&["sub".to_string()], None, &global, dir.path()).unwrap();
    assert_eq!(out, vec!["sub/.env"]);
}

#[test]
fn resolve_directory_filepath_normalizes_like_node_path_join() {
    // The join is Node's path.join, which normalizes. Banner strings:
    //   `run -f . …`      → `⟐ injected env (2) from .env`      (NOT ./.env)
    //   `run -f ./ …`     → `⟐ injected env (2) from .env`
    //   `run -f sub/. …`  → `… from sub/.env`                   (NOT sub/./.env)
    //   `run -f sub …`    → `… from sub/.env`
    //   `run -f sub/ …`   → `… from sub/.env`
    //   `run -f .. …`     → `… from ../.env`
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let cwd = dir.path();
    let cases: &[(&str, &str)] = &[
        (".", ".env"),
        ("./", ".env"),
        (".//", ".env"),
        ("sub", "sub/.env"),
        ("sub/", "sub/.env"),
        ("sub/.", "sub/.env"),
        ("./sub", "sub/.env"),
        ("..", "../.env"),
    ];
    for (input, expected) in cases {
        assert_eq!(
            resolve_directory_filepath(input, ".env", cwd),
            *expected,
            "resolveDirectoryFilepath({input:?}, \".env\")"
        );
    }
    // Same class through the -fk resolution path.
    assert_eq!(
        resolve_env_keys_file(Some(vec![".".to_string(), "sub/.".to_string()]), cwd),
        Some(vec![".env.keys".to_string(), "sub/.env.keys".to_string()])
    );
    // Non-directories still pass through UNCHANGED (no normalization).
    assert_eq!(
        resolve_directory_filepath("./missing", ".env", cwd),
        "./missing"
    );
    assert_eq!(
        resolve_directory_filepath("sub/./.env", ".env", cwd),
        "sub/./.env"
    );
}

#[test]
fn build_env_file_paths_directory_with_convention_expands_into_directory() {
    // A directory arg plus a convention expands the convention list into that
    // directory (and suppresses the global prepend).
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let global = env_map(&[]);
    let out =
        build_env_file_paths(&["sub".to_string()], Some("nextjs"), &global, dir.path()).unwrap();
    assert_eq!(
        out,
        vec![
            "sub/.env.development.local",
            "sub/.env.local",
            "sub/.env.development",
            "sub/.env",
        ]
    );
}

#[test]
fn invalid_convention_propagates() {
    let global = env_map(&[]);
    let err = build_env_file_paths(&[], Some("bogus"), &global, Path::new("/tmp")).unwrap_err();
    assert_eq!(err.code(), Some("INVALID_CONVENTION"));
}

#[test]
fn expand_home_paths_expands_home() {
    let paths = vec!["~/.env".to_string(), ".env".to_string()];
    let out = expand_home_paths(Some(&paths), Some(Path::new("/home/<user>")));
    assert_eq!(
        out,
        vec!["/home/<user>/.env".to_string(), ".env".to_string()]
    );
}

#[test]
fn resolve_lexical_normalizes_without_fs() {
    assert_eq!(
        resolve_lexical(Path::new("/a/b"), "../c/./d"),
        PathBuf::from("/a/c/d")
    );
    assert_eq!(
        resolve_lexical(Path::new("/a"), "/x/../y"),
        PathBuf::from("/y")
    );
}
