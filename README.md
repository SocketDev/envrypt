# envrypt

envrypt is a Rust library for encrypted `.env` files: it reads a `.env`, resolves
the private key from the process environment or `.env.keys`, decrypts
`encrypted:` values, and returns a map - or injects into `std::env` on request.

The private key stays out of your repo, your shell history, and your terminal
transcripts: the embedding app calls the library, and the key lives in an env var
or an approved secret broker. Local development with Sockeye injects the key
into one Touch-ID-approved child; CI injects it through its secret store.

```rust
// Reads ".env", resolves the key (env var → .env.keys),
// decrypts, and returns the values WITHOUT mutating std::env. Strict by default:
// an undecryptable value is an Err, never Ok carrying ciphertext.
let loaded = envrypt::load()?;
let token = loaded.get("STRIPE_SECRET");
```

`envrypt::config(&LoadOptions)` exposes the full surface: file paths, conventions,
strict vs best-effort, `inject` into `std::env` (default `false`), key-var naming,
and custom key resolvers. See [`crates/envrypt/README.md`](crates/envrypt/README.md).
For a local agent-safe setup, see [Sockeye integration](docs/envrypt/sockeye.md).

New values are encrypted in the **v3 format**: X25519 + XChaCha20-Poly1305 with a
key-committing check, the variable name bound into the AAD (so a ciphertext moved
onto another variable fails to decrypt), and Argon2id for passphrase mode. Spec:
[`docs/envrypt/crypto-v3.md`](docs/envrypt/crypto-v3.md). The legacy v1
`encrypted:`/`locked:` layouts remain readable
([`docs/envrypt/crypto-formats.md`](docs/envrypt/crypto-formats.md)), so existing
encrypted files keep decrypting.

## Repo layout

- `crates/envrypt` - the library crate (see its [README](crates/envrypt/README.md)
  and `examples/`).
- `crates/test-support` - dev-only test harness.
- `conformance/` - parser corpora, golden crypto vectors, and the frozen legacy
  interop corpus, driven by the `envrypt-conformance` runner.
- `docs/envrypt/` - `crypto-v3.md` (write format), `crypto-formats.md` (legacy
  read formats), `test-partition.md` (test map), `fuzzing.md`.
- `fuzz/` - libFuzzer targets and corpora (`docs/envrypt/fuzzing.md`).

## Compatibility

- **envrypt writes v3 and reads v3 + legacy v1.** Any `encrypted:` / `locked:` v1
  value in the supported wire format still decrypts under envrypt **given the
  key** (proven by the interop tripwire,
  `crates/envrypt/tests/interop_corpus.rs`).
- **Key-identifier names use the `ENVRYPT_` prefix:** the default key env vars are
  `ENVRYPT_PRIVATE_KEY[_<ENV>]` / `ENVRYPT_PUBLIC_KEY[_<ENV>]`; the prefix and
  explicit var names are configurable.
- The Rust API may still change; the wire and file formats are the stable
  contract.

## License

MIT - see [`LICENSE`](LICENSE).
