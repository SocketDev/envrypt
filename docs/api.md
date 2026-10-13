# Rust API

envrypt is a Rust library. It does not provide a command-line interface. The
crate root exposes a curated API for reading `.env` files, resolving keys, and
encrypting values.

```rust,no_run
use envrypt::{config, LoadOptions};

let loaded = config(&LoadOptions::default())?;
if let Some(token) = loaded.get("STRIPE_SECRET") {
    // Use the decrypted value without printing it.
    let _ = token;
}
# Ok::<(), envrypt::LoadError>(())
```

`load() -> Result<Loaded, LoadError>` reads the default `.env` and sibling
`.env.keys` locations. `config(&LoadOptions) -> Result<Loaded, LoadError>` uses
the supplied paths and policies. The default is strict, reads key material from
the process environment and `.env.keys`, and does not mutate `std::env`.

`Loaded` provides `get`, insertion-order `iter`, `len`, `is_empty`,
`into_env_map`, and `errors`. Its `Debug` output redacts values. `LoadError`
provides `code() -> Option<&str>` and `message() -> &str`; in strict mode an
unresolved or undecryptable value returns `Err` rather than a value containing
ciphertext. With `strict: false`, loadable values are returned and
best-effort failures are available from `Loaded::errors()`.

`LoadOptions` configures file paths, dotenv conventions, override behavior,
key naming, diagnostics, and secret resolvers. `KeyPolicy::EnvOnly` is the
default; `SystemKeychain` opts into OS keychain reads, and `Custom` supplies
`KeyResolver` implementations. Environment injection is opt-in through
`inject: true` and mutates process-global state. External secret CLI resolvers
such as 1Password or AWS are individually opt-in and disabled by default.

The value-level API exports `encrypt`, `decrypt`, `keypair_v3`, `V3Keypair`,
`V3Error`, and `CryptoError`. Writes use the v3 format; reads also support the
frozen v1 layouts. See the [v3 write format](envrypt/crypto-v3.md) and
[v1 read formats](envrypt/crypto-formats.md).

The hosted [crate API documentation](https://docs.rs/envrypt/latest/envrypt/)
lists the complete Rust types and methods. The API may change before 1.0; the
encrypted value formats have a separate compatibility contract.

## Format references

- [v3 write format](envrypt/crypto-v3.md)
- [v1 read formats](envrypt/crypto-formats.md)

For usage and development setup, see the [crate README](../crates/envrypt/README.md).
