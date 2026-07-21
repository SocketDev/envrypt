//! The public-API safety guarantees: no env mutation by default, strict-by-default
//! errors, the custom key-resolver seam, and error reporting through an accessor.

use std::sync::{Arc, Mutex};

use envrypt::{config, Diagnostic, DiagnosticLevel, KeyPolicy, KeyResolver, LoadOptions};

fn write_env(dir: &std::path::Path, name: &str, contents: &str) -> std::path::PathBuf {
  let p = dir.join(name);
  std::fs::write(&p, contents).unwrap();
  p
}

// A plaintext `.env` loads and reads back; the process env stays untouched because
// inject defaults to false.
#[test]
fn plaintext_loads_without_mutating_env() {
  let dir = tempfile::tempdir().unwrap();
  let env_path = write_env(dir.path(), ".env", "PLAIN_KEY_XYZ=hello world\n");

  let opts = LoadOptions {
    path: Some(vec![env_path]),
    ..Default::default()
  };
  let loaded = config(&opts).expect("plaintext load");
  assert_eq!(loaded.get("PLAIN_KEY_XYZ"), Some("hello world"));
  assert_eq!(loaded.len(), 1);
  assert!(!loaded.is_empty());
  assert_eq!(
    loaded.iter().collect::<Vec<_>>(),
    [("PLAIN_KEY_XYZ", "hello world")]
  );
  assert_eq!(
    loaded
      .into_env_map()
      .get("PLAIN_KEY_XYZ")
      .map(String::as_str),
    Some("hello world")
  );

  // Default inject=false: the process env is untouched.
  assert!(
    std::env::var_os("PLAIN_KEY_XYZ").is_none(),
    "load() must not mutate std::env by default"
  );
}

// Under the default strict mode an undecryptable value returns `Err`; a strict load
// keeps `encrypted:` ciphertext out of the returned map.
#[test]
fn strict_by_default_errors_on_undecryptable() {
  let kp = envrypt::keypair_v3();
  let secret = envrypt::encrypt(&kp.public_key, "World", "SECRET").unwrap();
  let dir = tempfile::tempdir().unwrap();
  let env_path = write_env(
    dir.path(),
    ".env",
    &format!(
      "ENVRYPT_PUBLIC_KEY=\"{}\"\nSECRET=\"{}\"\n",
      kp.public_key, secret
    ),
  );

  // No key available anywhere → strict load fails.
  let opts = LoadOptions {
    path: Some(vec![env_path]),
    policy: KeyPolicy::EnvOnly, // don't consult the keychain
    ..Default::default()
  };
  let err = config(&opts).expect_err("strict must Err on an undecryptable value");
  assert_eq!(err.code(), Some("DECRYPTION_FAILED"));
  assert!(err.message().contains("DECRYPTION_FAILED"));
  assert_eq!(err.to_string(), err.message());
}

// A `KeyPolicy::Custom` resolver (the narrow `resolve(pubkey) -> Option<String>`
// seam) supplies the private key and the value decrypts.
#[test]
fn custom_resolver_decrypts() {
  let kp = envrypt::keypair_v3();
  let secret = envrypt::encrypt(&kp.public_key, "World", "SECRET").unwrap();
  let dir = tempfile::tempdir().unwrap();
  let env_path = write_env(
    dir.path(),
    ".env",
    &format!(
      "ENVRYPT_PUBLIC_KEY=\"{}\"\nSECRET=\"{}\"\n",
      kp.public_key, secret
    ),
  );

  struct FixedKey {
    public_key: String,
    private_key: String,
  }
  impl KeyResolver for FixedKey {
    fn resolve(&self, public_key_hex: &str) -> Option<String> {
      (public_key_hex == self.public_key).then(|| self.private_key.clone())
    }
  }

  let opts = LoadOptions {
    path: Some(vec![env_path]),
    policy: KeyPolicy::Custom(vec![Arc::new(FixedKey {
      public_key: kp.public_key.clone(),
      private_key: kp.private_key.clone(),
    })]),
    ..Default::default()
  };
  let loaded = config(&opts).expect("custom resolver decrypts");
  assert_eq!(loaded.get("SECRET"), Some("World"));
}

#[test]
fn custom_key_names_are_used_for_public_key_resolution() {
  let kp = envrypt::keypair_v3();
  let secret = envrypt::encrypt(&kp.public_key, "World", "SECRET").unwrap();
  let dir = tempfile::tempdir().unwrap();
  let env_path = write_env(
    dir.path(),
    ".env",
    &format!(
      "APP_PUBLIC_KEY=\"{}\"\nSECRET=\"{}\"\n",
      kp.public_key, secret
    ),
  );

  struct FixedKey(String);
  impl KeyResolver for FixedKey {
    fn resolve(&self, _: &str) -> Option<String> {
      Some(self.0.clone())
    }
  }

  let loaded = config(&LoadOptions {
    path: Some(vec![env_path]),
    key_prefix: Some("APP_".to_string()),
    policy: KeyPolicy::Custom(vec![Arc::new(FixedKey(kp.private_key))]),
    ..Default::default()
  })
  .expect("custom prefix resolves the matching public key");
  assert_eq!(loaded.get("SECRET"), Some("World"));
}

// Non-strict mode reports the decrypt error through the `Loaded::errors()` accessor
// and the `on_diagnostic` callback.
#[test]
fn non_strict_reports_errors_via_accessor() {
  let kp = envrypt::keypair_v3();
  let secret = envrypt::encrypt(&kp.public_key, "World", "SECRET").unwrap();
  let dir = tempfile::tempdir().unwrap();
  let env_path = write_env(
    dir.path(),
    ".env",
    &format!(
      "ENVRYPT_PUBLIC_KEY=\"{}\"\nSECRET=\"{}\"\n",
      kp.public_key, secret
    ),
  );

  let diagnostics = Arc::new(Mutex::new(Vec::<Diagnostic>::new()));
  let sink = diagnostics.clone();
  let opts = LoadOptions {
    path: Some(vec![env_path]),
    policy: KeyPolicy::EnvOnly,
    strict: false,
    on_diagnostic: Some(Box::new(move |d| sink.lock().unwrap().push(d))),
    ..Default::default()
  };
  let loaded = config(&opts).expect("non-strict returns Ok");
  assert!(
    !loaded.errors().is_empty(),
    "non-strict surfaces the decrypt error via errors()"
  );
  // The diagnostics callback also saw the error line.
  assert!(diagnostics.lock().unwrap().iter().any(|diagnostic| {
    diagnostic.level == DiagnosticLevel::Error && diagnostic.message.contains("DECRYPTION_FAILED")
  }));
}

#[test]
fn system_keychain_policy_keeps_plaintext_loads_local() {
  let dir = tempfile::tempdir().unwrap();
  let env_path = write_env(dir.path(), ".env", "PLAIN_KEY=hello\n");
  let loaded = config(&LoadOptions {
    path: Some(vec![env_path]),
    policy: KeyPolicy::SystemKeychain,
    ..Default::default()
  })
  .expect("a plaintext file needs no keychain lookup");
  assert_eq!(loaded.get("PLAIN_KEY"), Some("hello"));
}

// The curated root surface writes the v3 format and reads both generations
// (crypto-v3.md Compatibility): `envrypt::encrypt` emits a 0x03-versioned
// payload, `envrypt::decrypt` opens it bound to its variable name, and the same
// `decrypt` keeps opening v1 values.
#[test]
fn root_encrypt_writes_v3_and_root_decrypt_reads_both_generations() {
  let kp = envrypt::keypair_v3();
  let value = envrypt::encrypt(&kp.public_key, "hello", "TOKEN").unwrap();
  // A v3 recipient payload begins 0x03 0x01 (version, mode) → base64url "Aw…".
  assert!(
    value.starts_with("encrypted:Aw"),
    "root encrypt writes the v3 layout: {value}"
  );
  assert_eq!(
    envrypt::decrypt(&kp.private_key, &value, "TOKEN").unwrap(),
    "hello"
  );
  // The variable-name binding holds on the curated surface.
  assert!(envrypt::decrypt(&kp.private_key, &value, "OTHER").is_err());

  // The v1 layout stays readable through the same root decrypt (the v1 writer
  // in the internal engine keeps minting fresh compatibility vectors).
  let v1 = envrypt::crypto::keypair();
  let v1_value = envrypt::crypto::encrypt(&v1.public_key, "hello", true).unwrap();
  assert_eq!(
    envrypt::decrypt(&v1.private_key, &v1_value, "ANY_NAME").unwrap(),
    "hello"
  );
}
