# envrypt test map

What each test surface pins. The workspace runs with `cargo test --workspace`;
every surface below must stay green on every change.

## 1. Integration tests (`crates/envrypt/tests/`)

| File                | What it pins                                                                                                                                                                                                                                                                                                                                      |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `interop_corpus.rs` | **The legacy-read guarantee.** Decrypts/unlocks every value in `conformance/vectors/interop/interop.json` (8 `encrypted:` + 4 `locked:` v1 values) with the key directly. The checked-in JSON is the frozen artifact of record for the v1 layouts (`docs/envrypt/crypto-formats.md`); a red run is a stop-the-line bug, never a golden to update. |
| `crypto_v3.rs`      | The v3 write format (`docs/envrypt/crypto-v3.md`): round-trips for both modes, wrong-key/wrong-passphrase/wrong-name opacity, per-byte header tamper, commitment binding, relocation binding, nonce/salt uniqueness across batches, byte-for-byte key-schedule checks against the spec, and v1 values routing through the same entry points.      |
| `crypto_vectors.rs` | Golden `encrypted:` v1 decrypt vectors plus the frozen decrypt error strings (`conformance/vectors/crypto.json` `vectors[]`/`errors[]`; taxonomy in `crypto-formats.md` §1.4).                                                                                                                                                                    |
| `key_naming.rs`     | The `ENVRYPT_`-default key identifiers, the configurable prefix (`KeyNaming::from_prefix`), and the explicit `private_key_var` override.                                                                                                                                                                                                          |
| `public_api.rs`     | The `load()`/`config()` contract: strict-by-default `Err` on an undecryptable value, `inject = false` default, `KeyPolicy::Custom` resolvers, and the `Loaded::errors()` accessor.                                                                                                                                                                |

## 2. Unit tests (`#[cfg(test)]` in `crates/envrypt/src/**`)

Module-level coverage for parse (scan/expand/evaluate), crypto, edit,
conventions (`presets.rs` filepaths, `resolvers/envs.rs` ordering), keyring,
`fsio`, `keys_file`, `errors`, and `services/lock.rs` (`unlock_value`).

## 3. Parser conformance (`conformance/`)

The `envrypt-conformance` runner drives envrypt's parse pipeline over JSON
corpora and compares parsed maps (insertion-ordered equality).

| Surface                              | What it pins                                                                                                                             |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `runner/tests/parser_conformance.rs` | The 88 spec cases (`cases/spec/spec.json`) plus the encoding slice (`cases/parser/encoding.json`) against `parse_with_ring`.             |
| `runner/tests/tier1_spec.rs`         | The shape of the 88-case corpus. `cases/spec/spec.json` is the corpus of record for `.env` grammar semantics.                            |
| `cases/expand.yaml`                  | Reference corpus for expansion semantics (data only; expansion behavior is pinned by the spec cases and the `parse::expand` unit tests). |
| `vectors/crypto.json`                | Golden decrypt vectors + frozen error strings (consumed by `crypto_vectors.rs`).                                                         |
| `vectors/interop/interop.json`       | The frozen legacy-value corpus (consumed by `interop_corpus.rs`).                                                                        |
| `fixtures/{root,monorepo}/**`        | `.env` fixture trees consumed by `parser_conformance.rs`.                                                                                |

## 4. Fuzzing (`fuzz/`)

Three libFuzzer targets (`parse_pipeline`, `ecies_decrypt`, `upsert_roundtrip`)
run nightly in CI. Layout, seams, flags, and the crash-to-regression-test
protocol: `docs/envrypt/fuzzing.md`.
