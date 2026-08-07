# envrypt

envrypt is a Rust library that encrypts and decrypts `.env` values. It reads a
`.env`, resolves the private key from the process environment or `.env.keys`,
decrypts `encrypted:` values, and returns a map - or injects into `std::env` on
request.

The private key stays out of your repo, your shell history, and your terminal
transcripts: the embedding app calls the library, and the key lives in an env
var or a secret broker that starts the embedding process.

```rust
// Reads ".env", resolves the key (env var → .env.keys),
// decrypts, and returns the values WITHOUT mutating std::env. Strict by default:
// an undecryptable value is an Err, never Ok carrying ciphertext.
let loaded = envrypt::load()?;
let token = loaded.get("STRIPE_SECRET");
# Ok::<(), envrypt::LoadError>(())
```

## API

- `envrypt::load()` - zero-config: reads `.env`, default key resolution, returns
  a `Loaded` map.
- `envrypt::config(&LoadOptions)` - full control: file paths, conventions
  (`nextjs`, `flow`), `overload`, `strict`, `inject`, key naming, keychain
  timeout, a diagnostics callback, and a `KeyPolicy` (env-only default,
  opt-in system keychain, or custom `KeyResolver`s).

Behavior contracts, pinned by `tests/public_api.rs` and the keychain tests:

- **Strict by default.** An unresolved or undecryptable value returns
  `Err(LoadError)`. With `strict = false`, the ciphertext stays in the map and
  the failure is reported via `Loaded::errors()`.
- **`inject = false` by default.** `load()`/`config()` return the map and leave
  `std::env` untouched. With `inject = true`, call before spawning threads:
  `std::env::set_var` is process-global and unsafe under concurrent reads.
- **Safe default resolution:** process env → `.env.keys`. `KeyPolicy::SystemKeychain`
  is an explicit opt-in for embedding applications that deliberately accept the
  OS credential policy; `EnvOnly` and `Custom` remain available.
- **Read-only, bounded resolve.** `load()`/`config()` never write to the OS
  keychain. Each keychain subprocess runs under a bounded timeout (default
  ~2 s, `LoadOptions::keychain_timeout`); on timeout or spawn failure the
  provider yields nothing and resolution falls through to the env path.
- **Library purity.** The library talks to its caller through return values and
  the optional `on_diagnostic` callback; stdout, stderr, argv, and signal
  handlers belong to the embedding app.
- **Parsing runs no commands.** A `$(…)` sequence in a value is literal text,
  not a shell command. Parsing a `.env` spawns no child process, so a file an
  attacker can write cannot execute anything. This diverges from dotenvx, which
  shells `$(…)` out; the four affected corpus cases are marked in
  `conformance/README.md`.
- **The private key never leaves.** A `.env` line named after the configured
  private key (`ENVRYPT_PRIVATE_KEY*` by default) is dropped from the returned
  map and from anything `inject` writes, so a planted line cannot carry the
  resolved key out to the caller or to `std::env`.
- **Bounded expansion.** `${VAR}` expansion is capped at
  `LoadOptions::max_expand_output_bytes` (default 1 MiB) per value. A
  self-referential value that grows on every pass returns `EXPANSION_TOO_LARGE`
  naming the key; the value is reported, never truncated.

## Encryption format

New values are written in the v3 format (`docs/envrypt/crypto-v3.md`): X25519 +
XChaCha20-Poly1305 with a key-commitment check, the variable name bound into the
AAD, and Argon2id for passphrase mode.

## Sockeye and OS keychains

For local agent work, use Sockeye to start the exact trusted program with
`ENVRYPT_PRIVATE_KEY`; Envrypt's default policy consumes that environment value
without another credential read. The `SystemKeychain` policy retains the former
cross-platform keychain reader as an explicit embedding choice. Envrypt no
longer offers a keychain write API because macOS `security(1)` requires the
secret as a command argument.

## Compatibility

- **envrypt writes v3 and reads v3 + legacy v1.** Any `encrypted:` / `locked:`
  v1 value in the supported wire format still decrypts under envrypt **given
  the key** (`docs/envrypt/crypto-formats.md`; proven by
  `tests/interop_corpus.rs`).
- **Key-identifier names use the `ENVRYPT_` prefix.** The default private/public
  key env vars are `ENVRYPT_PRIVATE_KEY[_<ENV>]` / `ENVRYPT_PUBLIC_KEY[_<ENV>]`;
  the prefix (`LoadOptions::key_prefix`) and explicit var names
  (`private_key_var` / `public_key_var`) are configurable.
- The Rust API may still change; the wire and file formats are the stable
  contract.

## License

MIT - see `LICENSE`.
