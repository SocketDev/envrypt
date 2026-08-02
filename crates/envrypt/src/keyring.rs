//! Key resolution: the two-phase keyring.
//!
//! Phase 1 ([`keyring_local`]) resolves keys from `.env.keys` files and
//! `process.env` alone — no providers, no network. Phase 2 ([`fill_ring`]) runs
//! [`crate::providers::KeyProvider`]s to fill the ring's blank entries. The
//! resulting [`Ring`] is the exact value `crate::parse::parse_with_ring`
//! consumes: compressed-pubkey hex maps to private-key hex, and `""` marks an
//! unfilled seed.
//!
//! Phase 1 builds the ring in a fixed order, and that order decides which key
//! wins when two entries derive the same public key:
//! 1. start from the seed ring (each `publickeys(src)` value maps to `""`, in
//!    publickeys order);
//! 2. collect every `ENVRYPT_PRIVATE_KEY*` value from the keys files (all
//!    occurrences, each split on `,`), in file order — FILE keys first;
//! 3. scan `process.env`: seed each `ENVRYPT_PUBLIC_KEY*` VALUE (insert `""` only
//!    when absent) and append each `ENVRYPT_PRIVATE_KEY*` value to the
//!    private-key list — ENV keys after file keys;
//! 4. for each collected private key, set `ring[derive(pk)] = pk` (skipping
//!    invalid keys). An env key that shares a derived public key with a file key
//!    overwrites it, so env wins over file. The insertion order is seeds →
//!    env-public-values → file-derived → env-derived, pinned by
//!    `insertion_order_seeds_env_public_file_derived_env_derived`.
//!
//! The ring is built ONCE via [`Keyring`] and reused across files. Rotate-family
//! commands that write `.env.keys` call [`Keyring::rebuild`] after the write so
//! the ring picks up the new keys.

use crate::conventions::keynames::{default_key_naming, KeyNaming};
use crate::providers::{KeyProvider, ProviderError};
use indexmap::IndexMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// The keyring: compressed-pubkey hex maps to private-key hex; `""` marks an
/// unfilled seed awaiting a provider. This is the map `parse_with_ring` consumes;
/// insertion order sets the decrypt-attempt order.
pub type Ring = IndexMap<String, String>;

/// Default keys-file name.
pub const DEFAULT_KEYS_FILENAME: &str = ".env.keys";

/// The default keys-file list: a single relative `.env.keys`, resolved against
/// the process cwd.
pub fn default_fk() -> Vec<PathBuf> {
    vec![PathBuf::from(DEFAULT_KEYS_FILENAME)]
}

/// Inputs to [`keyring_local`], the file-and-env phase.
pub struct KeyringLocalOptions<'a> {
    /// The process-env map to scan for the configured public/private key names.
    pub process_env: &'a IndexMap<String, String>,
    /// Keys files to read (default [`default_fk`]).
    pub fk: Vec<PathBuf>,
    /// Seed ring: each public key maps to `""` before phase 1 fills it. Sets the
    /// leading insertion order and which blanks a provider may fill.
    pub seed_ring: Ring,
    /// The key-identifier naming (default `ENVRYPT_`). A consumer may set a
    /// different prefix or explicit variable names.
    pub naming: &'a KeyNaming,
}

impl<'a> KeyringLocalOptions<'a> {
    /// Options over `process_env` with the default `fk`, empty seed ring, and the
    /// default `ENVRYPT_` naming.
    pub fn new(process_env: &'a IndexMap<String, String>) -> Self {
        Self {
            process_env,
            fk: default_fk(),
            seed_ring: Ring::new(),
            naming: default_key_naming(),
        }
    }
}

/// Phase 1: build the ring from `.env.keys` files + `process.env` only.
pub fn keyring_local(opts: &KeyringLocalOptions) -> Ring {
    let mut ring = opts.seed_ring.clone();

    // (2) file private keys first, in fk order (all occurrences, comma-split).
    let mut private_keys: Vec<String> = Vec::new();
    for path in &opts.fk {
        collect_file_private_keys(path, &mut private_keys, opts.naming);
    }

    // (3) process.env: seed public-key values, append private-key values.
    for (name, value) in opts.process_env {
        if opts.naming.is_public_key_name(name) {
            // Insert `""` only when absent; keep an existing (possibly filled)
            // entry in place.
            ring.entry(value.clone()).or_default();
        }
        if opts.naming.is_private_key_name(name) {
            private_keys.push(value.clone());
        }
    }

    // (4) derive each private key and set `ring[derived_pub] = private_key`.
    // Invalid keys are skipped. `IndexMap::insert` keeps an existing key's
    // position while updating its value, so the env-after-file order yields
    // "env wins over file" on a shared derived public key.
    for private_key in &private_keys {
        if let Ok(secret) = crate::crypto::parse_private_key(private_key) {
            let public_hex = crate::crypto::public_key_hex(&secret);
            ring.insert(public_hex, private_key.clone());
        }
    }
    clear_private_keys(&mut private_keys);

    ring
}

/// Overwrites every private-key allocation held by a resolver ring.
pub fn clear_ring(ring: &mut Ring) {
    for private_key in ring.values_mut() {
        private_key.zeroize();
    }
    ring.clear();
}

fn clear_private_keys(private_keys: &mut [String]) {
    for private_key in private_keys {
        private_key.zeroize();
    }
}

/// Collect every configured `<prefix>PRIVATE_KEY*` value from a keys file into
/// `out` (all occurrences, each split on `,`). Any read failure (missing file, a
/// directory, …) is ignored.
fn collect_file_private_keys(path: &Path, out: &mut Vec<String>, naming: &KeyNaming) {
    // Read as lossy UTF-8, preserving any leading BOM, which `scan`'s whitespace
    // class handles.
    let Ok(mut src) = crate::fsio::read_file_x(path, Some(crate::fsio::FileEncoding::Utf8)) else {
        return;
    };
    for (name, values) in crate::parse::scan(&src, &crate::parse::ScanOptions::default()) {
        if naming.is_private_key_name(&name) {
            for value in values {
                for part in value.split(',') {
                    out.push(part.to_string());
                }
            }
        }
    }
    src.zeroize();
}

/// Phase 2: run providers to fill the ring's blank (`""`-valued) entries.
/// Providers run in order and each fills only blanks, so the first provider that
/// resolves a given public key wins. When the ring has no blanks the providers
/// are never invoked.
pub fn fill_ring(
    ring: &mut Ring,
    providers: &[Box<dyn KeyProvider>],
    on_status: &mut dyn FnMut(&str),
) -> Result<(), ProviderError> {
    if !ring.values().any(String::is_empty) {
        return Ok(());
    }
    for provider in providers {
        provider.lookup(ring, on_status)?;
    }
    Ok(())
}

/// A process-lifetime keyring: built ONCE from files and env, reused across
/// parses, with an explicit [`rebuild`](Keyring::rebuild) hook for the rotate
/// family. The inner [`Ring`] is what `parse_with_ring` consumes via
/// [`ring`](Keyring::ring).
pub struct Keyring {
    ring: Ring,
}

impl Keyring {
    /// Build the file+env ring (phase 1).
    pub fn local(opts: &KeyringLocalOptions) -> Self {
        Self {
            ring: keyring_local(opts),
        }
    }

    /// Re-run phase 1 after `.env.keys` was written (rotate-family write sites).
    pub fn rebuild(&mut self, opts: &KeyringLocalOptions) {
        clear_ring(&mut self.ring);
        self.ring = keyring_local(opts);
    }

    /// Phase 2: fill blanks in-place via providers.
    pub fn fill(
        &mut self,
        providers: &[Box<dyn KeyProvider>],
        on_status: &mut dyn FnMut(&str),
    ) -> Result<(), ProviderError> {
        fill_ring(&mut self.ring, providers, on_status)
    }

    /// Borrow the ring for `parse_with_ring`.
    pub fn ring(&self) -> &Ring {
        &self.ring
    }

    /// Consume into the owned ring.
    pub fn into_ring(mut self) -> Ring {
        std::mem::take(&mut self.ring)
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
        clear_ring(&mut self.ring);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{keypair, Keypair};
    use std::io::Write;

    fn env(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn write_keys(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join(".env.keys");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    fn local(process_env: &IndexMap<String, String>, fk: Vec<PathBuf>, seed: Ring) -> Ring {
        keyring_local(&KeyringLocalOptions {
            process_env,
            fk,
            seed_ring: seed,
            naming: default_key_naming(),
        })
    }

    // Two DIFFERENT private keys in the file → BOTH derived public keys land in
    // the ring (keyed by derived pubkey, not by variable name, so neither is
    // dropped).
    #[test]
    fn file_keeps_every_distinct_private_key() {
        let d = tempfile::tempdir().unwrap();
        let a = keypair();
        let b = keypair();
        let fk = write_keys(
            d.path(),
            &format!(
                "ENVRYPT_PRIVATE_KEY=\"{}\"\nENVRYPT_PRIVATE_KEY=\"{}\"\n",
                a.private_key, b.private_key
            ),
        );
        let ring = local(&env(&[]), vec![fk], Ring::new());
        assert_eq!(ring.get(&a.public_key), Some(&a.private_key));
        assert_eq!(ring.get(&b.public_key), Some(&b.private_key));
    }

    // Identical duplicate value → a single ring entry (derived-pubkey keyed,
    // second insert overwrites with the same value: effective last-wins).
    #[test]
    fn duplicate_identical_value_is_one_entry() {
        let d = tempfile::tempdir().unwrap();
        let a = keypair();
        let fk = write_keys(
            d.path(),
            &format!(
                "ENVRYPT_PRIVATE_KEY=\"{}\"\nENVRYPT_PRIVATE_KEY=\"{}\"\n",
                a.private_key, a.private_key
            ),
        );
        let ring = local(&env(&[]), vec![fk], Ring::new());
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.get(&a.public_key), Some(&a.private_key));
    }

    // Malformed private keys (bad hex, wrong length) are skipped; valid keys
    // still land.
    #[test]
    fn invalid_keys_silently_skipped() {
        let d = tempfile::tempdir().unwrap();
        let a = keypair();
        let fk = write_keys(
            d.path(),
            &format!(
                "ENVRYPT_PRIVATE_KEY=\"not-a-hex-key\"\nENVRYPT_PRIVATE_KEY=\"{}\"\nENVRYPT_PRIVATE_KEY=\"0000\"\n",
                a.private_key
            ),
        );
        let ring = local(&env(&[]), vec![fk], Ring::new());
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.get(&a.public_key), Some(&a.private_key));
    }

    // A comma-joined value carries multiple rotated keys.
    #[test]
    fn comma_split_multiple_keys_per_value() {
        let d = tempfile::tempdir().unwrap();
        let a = keypair();
        let b = keypair();
        let fk = write_keys(
            d.path(),
            &format!(
                "ENVRYPT_PRIVATE_KEY=\"{},{}\"\n",
                a.private_key, b.private_key
            ),
        );
        let ring = local(&env(&[]), vec![fk], Ring::new());
        assert_eq!(ring.len(), 2);
        assert!(ring.contains_key(&a.public_key));
        assert!(ring.contains_key(&b.public_key));
    }

    // env ENVRYPT_PRIVATE_KEY is appended AFTER file keys, so on a shared derived
    // public key it overwrites the file key — "env wins over file". With distinct
    // keys, both remain (seed order preserved).
    #[test]
    fn env_and_file_keys_both_resolved_in_seed_order() {
        let d = tempfile::tempdir().unwrap();
        let file_kp = keypair();
        let env_kp = keypair();
        let fk = write_keys(
            d.path(),
            &format!("ENVRYPT_PRIVATE_KEY=\"{}\"\n", file_kp.private_key),
        );
        let mut seed = Ring::new();
        seed.insert(file_kp.public_key.clone(), String::new());
        seed.insert(env_kp.public_key.clone(), String::new());
        let ring = local(
            &env(&[("ENVRYPT_PRIVATE_KEY", &env_kp.private_key)]),
            vec![fk],
            seed,
        );
        let keys: Vec<&String> = ring.keys().collect();
        assert_eq!(keys, vec![&file_kp.public_key, &env_kp.public_key]);
        assert_eq!(ring.get(&file_kp.public_key), Some(&file_kp.private_key));
        assert_eq!(ring.get(&env_kp.public_key), Some(&env_kp.private_key));
    }

    // Env key overwrites the file key when they derive to the SAME public key
    // (env wins over file) — one entry, env's value.
    #[test]
    fn env_overwrites_file_on_shared_public_key() {
        let d = tempfile::tempdir().unwrap();
        let shared: Keypair = keypair();
        let fk = write_keys(
            d.path(),
            &format!("ENVRYPT_PRIVATE_KEY=\"{}\"\n", shared.private_key),
        );
        let ring = local(
            &env(&[("ENVRYPT_PRIVATE_KEY", &shared.private_key)]),
            vec![fk],
            Ring::new(),
        );
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.get(&shared.public_key), Some(&shared.private_key));
    }

    // Insertion order: seed pub, then env public-key VALUE, then file-derived
    // pub, then env-derived pub.
    #[test]
    fn insertion_order_seeds_env_public_file_derived_env_derived() {
        let d = tempfile::tempdir().unwrap();
        let seed_kp = keypair();
        let file_kp = keypair();
        let env_kp = keypair();
        let fk = write_keys(
            d.path(),
            &format!("ENVRYPT_PRIVATE_KEY=\"{}\"\n", file_kp.private_key),
        );
        let mut seed = Ring::new();
        seed.insert(seed_kp.public_key.clone(), String::new());
        let ring = local(
            &env(&[
                ("ENVRYPT_PUBLIC_KEY_X", "envpubval"),
                ("ENVRYPT_PRIVATE_KEY_Y", &env_kp.private_key),
            ]),
            vec![fk],
            seed,
        );
        let keys: Vec<&str> = ring.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec![
                seed_kp.public_key.as_str(),
                "envpubval",
                file_kp.public_key.as_str(),
                env_kp.public_key.as_str(),
            ]
        );
    }

    // A missing keys file leaves the seed ring intact (blank retained).
    #[test]
    fn missing_keys_file_retains_seed_blanks() {
        let d = tempfile::tempdir().unwrap();
        let a = keypair();
        let mut seed = Ring::new();
        seed.insert(a.public_key.clone(), String::new());
        let ring = local(&env(&[]), vec![d.path().join("nope.keys")], seed);
        assert_eq!(ring.get(&a.public_key), Some(&String::new()));
    }

    // A fake provider that fills only blanks; `calls` is an `Rc<Cell>` so the
    // invocation count stays observable after the provider is boxed/moved.
    struct FillProvider {
        value: String,
        calls: std::rc::Rc<std::cell::Cell<usize>>,
    }
    impl KeyProvider for FillProvider {
        fn lookup(
            &self,
            ring: &mut Ring,
            on_status: &mut dyn FnMut(&str),
        ) -> Result<(), ProviderError> {
            self.calls.set(self.calls.get() + 1);
            on_status("provider ran");
            for (_pub, priv_hex) in ring.iter_mut() {
                if priv_hex.is_empty() {
                    *priv_hex = self.value.clone();
                }
            }
            Ok(())
        }
    }

    #[test]
    fn fill_ring_fills_blanks_only_and_forwards_on_status() {
        let mut ring = Ring::new();
        ring.insert("blankpub".into(), String::new());
        ring.insert("filledpub".into(), "already".into());
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let provider = FillProvider {
            value: "PROVIDED".into(),
            calls: calls.clone(),
        };
        let mut statuses: Vec<String> = Vec::new();
        let providers: Vec<Box<dyn KeyProvider>> = vec![Box::new(provider)];
        fill_ring(&mut ring, &providers, &mut |s| statuses.push(s.to_string())).unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(ring.get("blankpub"), Some(&"PROVIDED".to_string()));
        assert_eq!(ring.get("filledpub"), Some(&"already".to_string()));
        assert_eq!(statuses, vec!["provider ran".to_string()]);
    }

    #[test]
    fn fill_ring_skips_providers_when_no_blanks() {
        let mut ring = Ring::new();
        ring.insert("filledpub".into(), "already".into());
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let provider = FillProvider {
            value: "PROVIDED".into(),
            calls: calls.clone(),
        };
        let providers: Vec<Box<dyn KeyProvider>> = vec![Box::new(provider)];
        fill_ring(&mut ring, &providers, &mut |_| {}).unwrap();
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn clear_ring_removes_private_key_entries() {
        let mut ring = Ring::new();
        ring.insert("public-key".into(), "0123456789abcdef".into());
        clear_ring(&mut ring);
        assert!(ring.is_empty());
    }

    // Keyring struct: build once, rebuild after a keys-file rewrite.
    #[test]
    fn keyring_struct_build_once_and_rebuild() {
        let d = tempfile::tempdir().unwrap();
        let a = keypair();
        let fk_path = d.path().join(".env.keys");
        let process_env = env(&[]);

        let opts = KeyringLocalOptions {
            process_env: &process_env,
            fk: vec![fk_path.clone()],
            seed_ring: Ring::new(),
            naming: default_key_naming(),
        };
        let mut kr = Keyring::local(&opts);
        assert!(kr.ring().is_empty());

        // rotate-style write, then explicit rebuild.
        write_keys(
            d.path(),
            &format!("ENVRYPT_PRIVATE_KEY=\"{}\"\n", a.private_key),
        );
        kr.rebuild(&opts);
        assert_eq!(kr.ring().get(&a.public_key), Some(&a.private_key));
    }

    // The configurable-naming acceptance tests (default `ENVRYPT_`, a consumer
    // `DOTENV_` prefix, explicit `private_key_var`) live in the integration test
    // `tests/key_naming.rs` so the shipped `crates/*/src` tree carries no
    // `DOTENV_` identifier token.
}
