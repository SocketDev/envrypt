//! Criterion micro-bench for the keyring build (`keyring_build`).
//!
//! Guards the "build the ring ONCE per process" claim: `keyring_local` reads the
//! `.env.keys` file, scans it, and derives a compressed public key per private key
//! (one EC base-point mult each). The bench measures the full build cost over a
//! fixed 10-key `.env.keys`. Cost is per-key (10 derives), not size-proportional,
//! so it uses `Throughput::Elements(10)`.
//!
//! Benches link default features only.

use std::io::Write;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use envrypt::keyring::{keyring_local, KeyringLocalOptions};
use indexmap::IndexMap;

/// Ten fixed, valid secp256k1 private keys (generated once via
/// `envrypt::crypto::keypair()` and frozen here so the corpus is
/// deterministic and committed).
const PRIVATE_KEYS: [&str; 10] = [
  "b8120666e3c35c67529678147e7cbc09d280292dae9348bb7fd740f174506a9c",
  "b325e65a943fffec97046de63127ee934c7de93937d0334344aa1f27e2f1d37f",
  "dc826174cac7b4c6af0dca76e734a960b9a8f0d7dc226047eabec74de941c117",
  "7e8daaa86aefbe0beeff46e776a9289a9a0725feb07aa6ee302a7f0c4f372871",
  "77009e40dbf63c44b600922b3bd4520531d524b5a683e30a107c960f6136a5d3",
  "a206f4804b3d97193181dee0c6bbf863c5f6be69c09a8672e9f5e237bdb675c1",
  "ef9600e745df5f484f44bc743c9fd2833a0041d0dd2a157353976e90db724b43",
  "3e87703bc26583355b1f2b07e6c179edaa29ffda9dd3bd77a5af5a39b2b5a776",
  "4790c2321da9d8866beeee57a71e91bb359d3e382df775b74f363249439d0231",
  "957cd87cfaba4bd19f86c0d89bd141ee607c33af2b11790218e287b61e7e3da6",
];

/// Render the fixed `.env.keys` corpus (10 `DOTENV_PRIVATE_KEY_<i>` entries).
fn keys_file_contents() -> String {
  let mut src = String::new();
  for (i, key) in PRIVATE_KEYS.iter().enumerate() {
    src.push_str(&format!("DOTENV_PRIVATE_KEY_{i}=\"{key}\"\n"));
  }
  src
}

fn bench_keyring(c: &mut Criterion) {
  // Write the fixed `.env.keys` to a temp file once; keyring_local re-reads it
  // per call (the measured build includes file I/O + scan + 10 derives).
  let mut file = tempfile::NamedTempFile::new().expect("create temp .env.keys");
  file
    .write_all(keys_file_contents().as_bytes())
    .expect("write temp .env.keys");
  file.flush().expect("flush temp .env.keys");
  let path = file.path().to_path_buf();

  let process_env: IndexMap<String, String> = IndexMap::new();
  let opts = KeyringLocalOptions {
    process_env: &process_env,
    fk: vec![path],
    seed_ring: IndexMap::new(),
    naming: envrypt::conventions::keynames::default_key_naming(),
  };

  let mut group = c.benchmark_group("keyring");
  group.throughput(Throughput::Elements(PRIVATE_KEYS.len() as u64));
  group.bench_function("keyring_build", |b| {
    b.iter(|| black_box(keyring_local(black_box(&opts))));
  });
  group.finish();
}

criterion_group!(benches, bench_keyring);
criterion_main!(benches);
