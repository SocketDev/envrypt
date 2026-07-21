# Changelog

All notable changes to envrypt are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0 (`0.x`), the Rust API may change between minor versions; the encrypted
value and file formats are the frozen compatibility contract.

## [Unreleased]

### Added

- **`sockeye`** — read one-shot envrypt credentials
- **`envrypt`** — initial release: a Rust library (no CLI) for encrypted `.env` files — reads a `.env`, and encrypts, decrypts, and generates keypairs for its `encrypted:` values.
- **`load` / `config`** — load a `.env`, resolve the private key, and return the decrypted environment.
- **`keys`** — private-key resolution through a configurable provider chain (environment variable → OS keychain).
- **`formats`** — reads the existing `encrypted:` and `locked:` value formats.
- **`crypto`** — `encrypt` seals a plaintext to an X25519 public key as an `encrypted:` value, `decrypt` opens it with the private key, and `keypair` generates a recipient identity.
- **`op://`** — opt-in 1Password secret resolution: with `resolve_op_references`, a value like `API_KEY="op://Personal/KEY/password"` is replaced with the secret read from the 1Password CLI at load time. Off by default; fail-closed (an unresolvable reference errors, never a silent pass-through).
- **`bw://`** — opt-in Bitwarden secret resolution: with `resolve_bw_references`, a value like `API_KEY="bw://<item-uuid>/password"` is replaced with the secret read from the Bitwarden CLI (`bw get`, using the unlocked `BW_SESSION`) at load time. Off by default; fail-closed.
- **more secret managers** — opt-in, fail-closed resolution for HashiCorp Vault (`vault://`), AWS Secrets Manager (`aws://`), Doppler (`doppler://`), GCP Secret Manager (`gcp://`), Azure Key Vault (`azure://`), Infisical (`infisical://`), and `pass` (`pass://`), each shelling the vendor CLI. See `docs/envrypt/secret-resolvers.md`.
- **`upsert`** — set a key's value in `.env` source text, updating the last occurrence in place or appending a `KEY=value` line.
- **`mask`** — redact a secret to a masked form for safe display or logging.
- **`json_to_env`** — convert a JSON object of values into `.env` text.

### Fixed

- **`deps`** — absorb the fleet catalog heal
- **`fleet`** — restore fetch-fleet-bundle to the v1.0.14 manifest bytes
- **`deps`** — override js-yaml to 5.2.2 for GHSA-pm4m-ph32-ghv5
- **`deps`** — add missing lockfile importers for fleet hook packages
- **`lint`** — scope expect markers for disallowed current\_dir at cwd-contract sites
- **`conformance`** — skip POSIX-shell command-substitution cases on Windows
- **`paths`** — `.env` file paths resolve correctly on Windows.
- **`secrets`** — resolver key material is zeroized after use.
- **`sockeye`** — one-shot credentials are read through sockeye, the safe local path.
