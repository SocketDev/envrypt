//! Criterion micro-benches for the ECIES crypto core (`encrypt_bulk_100`,
//! `decrypt_bulk_100`).
//!
//! Round-trip correctness of the crypto core is pinned by the vector and interop
//! tests (`crypto_vectors.rs`/`interop_corpus.rs`), never by ciphertext
//! byte-compare: `encrypted:` encryption is randomized
//! (docs/envrypt/crypto-formats.md §1.3). These benches only measure per-value cost.
//!
//! Both benches measure the hoisted per-value path. The write and read actions
//! parse the recipient/identity key ONCE per file, so `encrypt_bulk_100` calls
//! `parse_public_key` once at setup then `encrypt_with_key` in the loop, and
//! `decrypt_bulk_100` calls `parse_private_key` once then `decrypt_with_key` in the
//! loop. Each isolates the ECIES per-value floor from the one-time key-parse cost.
//! Crypto cost is dominated by the fixed-cost ECDH scalar mult, not the value
//! length, so these use `Throughput::Elements(100)` rather than `Throughput::Bytes`.
//!
//! Benches link default features only.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use envrypt::crypto::{
  decrypt_with_key, encrypt, encrypt_with_key, parse_private_key, parse_public_key,
};

/// Fixed test keypair — `tests/lib/helpers/decryptKeyValue.test.js:6-7`, a
/// test-only key published in the upstream reference repo's test suite.
const PUBLIC_KEY: &str = "02b106c30579baf896ae1fddf077cbcb4fef5e7d457932974878dcb51f42b45498";
const PRIVATE_KEY: &str = "1fc1cafa954a7a2bf0a6fbff46189c9e03e3a66b4d1133108ab9fcdb9e154b70";

const VALUE_COUNT: usize = 100;

/// 100 fixed plaintext values (deterministic, no randomness in the corpus).
fn plaintext_values() -> Vec<String> {
  (0..VALUE_COUNT)
    .map(|i| format!("secret-value-number-{i:03}-payload-abcdefghijklmnop"))
    .collect()
}

fn bench_crypto(c: &mut Criterion) {
  let mut group = c.benchmark_group("crypto");

  let plaintexts = plaintext_values();

  // encrypt_bulk_100 — write side: parse the recipient public key ONCE (outside
  // the measured loop, like the encrypt action does per file), then measure ONLY
  // `encrypt_with_key` per value. This isolates the per-value cost from the
  // one-time recipient parse.
  let recipient = parse_public_key(PUBLIC_KEY).expect("fixed test public key parses");
  group.throughput(Throughput::Elements(VALUE_COUNT as u64));
  group.bench_function("encrypt_bulk_100", |b| {
    b.iter(|| {
      for value in &plaintexts {
        black_box(encrypt_with_key(
          black_box(&recipient),
          black_box(value),
          true,
        ));
      }
    });
  });

  // decrypt_bulk_100 — ECIES per-value floor + hoist. Setup encrypts the fixed
  // plaintexts once (outside the measured loop) and parses the private key once
  // (`SecretKey`), then the loop measures ONLY `decrypt_with_key` per value.
  let ciphertexts: Vec<String> = plaintexts
    .iter()
    .map(|value| encrypt(PUBLIC_KEY, value, true).unwrap())
    .collect();
  let secret = parse_private_key(PRIVATE_KEY).expect("fixed test private key parses");
  group.throughput(Throughput::Elements(VALUE_COUNT as u64));
  group.bench_function("decrypt_bulk_100", |b| {
    b.iter(|| {
      for ciphertext in &ciphertexts {
        black_box(decrypt_with_key(black_box(&secret), black_box(ciphertext), true).unwrap());
      }
    });
  });

  group.finish();
}

criterion_group!(benches, bench_crypto);
criterion_main!(benches);
