//! # envrypt
//!
//! Read a `.env`, resolve the private key from a provider chain (process env first,
//! then the OS keychain), decrypt `encrypted:` values, and return a map — or inject
//! into `std::env`. A pure Rust library: the embedding app owns the feature, the
//! private key stays out of disk and shell history. For agent-controlled local
//! work, Sockeye delivers the key to one approved child through a one-shot
//! inherited descriptor.
//! License and attribution live in `LICENSE`.
//!
//! The curated, hard-to-misuse public API is at the crate root: [`load`], [`config`],
//! [`LoadOptions`], [`KeyPolicy`], [`KeyResolver`], [`Loaded`],
//! [`encrypt`]/[`decrypt`]/[`keypair_v3`], and [`EnvryptError`]. Value writes use the
//! v3 format (`docs/envrypt/crypto-v3.md`); reads cover v3 and the frozen v1 layouts.
//! Everything else (parse / keyring / providers / resolvers) is `#[doc(hidden)]`
//! internal engine.
//!
//! ```no_run
//! let loaded = envrypt::load()?;                 // strict; no std::env mutation
//! let token = loaded.get("STRIPE_SECRET");
//! # let _ = token;
//! # Ok::<(), envrypt::LoadError>(())
//! ```
//!
//! ## Compatibility & versioning
//! - **Crypto/file compat is frozen:** any `encrypted:` / `locked:` v1 value in the
//!   frozen wire format decrypts under envrypt **given the key**
//!   (`tests/interop_corpus.rs`).
//! - **Key-identifier names default to `ENVRYPT_`**; the prefix and explicit var
//!   names are configurable ([`LoadOptions::key_prefix`] etc.).
//! - **Pre-1.0 (`0.x`):** the Rust API may change between minor releases; the wire/file
//!   formats are the real frozen compat contract. **MSRV 1.80**, edition 2021.
//!   [`LoadOptions::inject`] mutates `std::env` and must be called before spawning
//!   threads (`std::env::set_var` becomes `unsafe` under edition 2024).
//!
//! ## Dependency hygiene
//! The default build links no HTTP/async stack — `cargo tree -e normal` shows no
//! `openssl-sys`/`tokio`/`reqwest`/`hyper` and no `clap`/`signal-hook`/`nix`/
//! `portable-pty`; CI enforces a positive allowlist.
#![deny(missing_docs)]

// --- Internal engine (doc-hidden): the modules the curated API wraps. They stay `pub`
// for the crate's own tests/benches/conformance, but are not a stable public surface. ---
#[doc(hidden)]
// The curated public API: load()/config()/LoadOptions/KeyPolicy/KeyResolver/Loaded,
// EnvryptError, and the safe encrypt/decrypt
// re-exports.
mod api;
#[doc(hidden)]
pub mod conventions;
#[doc(hidden)]
pub mod crypto;
pub mod crypto_v3;
#[doc(hidden)]
pub mod edit;
#[doc(hidden)]
pub mod errors;
#[doc(hidden)]
pub mod fsio;
#[doc(hidden)]
pub mod helpers;
#[doc(hidden)]
pub mod keyring;
#[doc(hidden)]
pub mod output;
#[doc(hidden)]
pub mod parse;
#[doc(hidden)]
pub mod providers;
#[doc(hidden)]
pub mod resolvers;
#[doc(hidden)]
pub mod services;
#[doc(hidden)]
pub mod sockeye;
pub use api::*;
