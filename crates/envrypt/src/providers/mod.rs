//! Key providers — phase-2 fillers of the two-phase keyring.
//!
//! The [`KeyProvider`] trait (this file) lets `keyring_local()` (file-and-env
//! only) be followed by providers that resolve the ring's blank (`""`-valued)
//! entries. The provider is [`keychain::KeychainProvider`], behind an
//! [`keychain::Exec`] trait so the absolute path `/usr/bin/security` can be faked
//! on any OS.
//!
//! ## Provider phase semantics
//! Two facts the trait and impls honor:
//!   1. A provider is **consulted only while the ring has a blank**. When every
//!      entry is truthy, [`crate::keyring::fill_ring`] short-circuits and no
//!      provider runs. A provider consults one public key at a time, in ring
//!      order, SKIPPING any entry filled by an earlier consult in the same pass.
//!   2. The merge writes **every truthy** entry a provider returns, NOT just the
//!      requested key. So a provider **CAN overwrite an already-filled ring
//!      entry** and can add brand-new keys. In practice the keychain provider
//!      returns only `{ <requested_pub>: priv }`, so overwrite is never observed,
//!      but the merge stays faithful to the write-every-truthy rule.
//!
//! Running a `&[Box<dyn KeyProvider>]` in order yields first-provider-wins per
//! public key: each `lookup` fills the blanks IT can, and a later provider
//! consults only entries still blank.

use crate::keyring::Ring;

/// A phase-2 key provider. `lookup` inspects `ring` and resolves any blank
/// (`""`-valued) entry it can, merging results by the write-every-truthy rule
/// (see the module docs — it MAY overwrite an already-filled entry). `on_status`
/// forwards human-readable progress strings. A provider is only ever invoked by
/// [`crate::keyring::fill_ring`] while the ring still has a blank.
pub trait KeyProvider {
  fn lookup(&self, ring: &mut Ring, on_status: &mut dyn FnMut(&str)) -> Result<(), ProviderError>;
}

/// A provider failure. Providers normally swallow their own errors and yield
/// `{}`, so `lookup` returns `Ok`; this carries a message for the rare case a
/// provider chooses to propagate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderError(pub String);

impl std::fmt::Display for ProviderError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.0)
  }
}

impl std::error::Error for ProviderError {}

/// Merge a provider's returned entries into the ring: every entry with a
/// non-empty value is written, overwriting an existing entry or adding a new one
/// (see module-doc fact 2). New keys are appended; existing keys keep their
/// position.
pub(crate) fn merge_truthy<I, K, V>(ring: &mut Ring, entries: I)
where
  I: IntoIterator<Item = (K, V)>,
  K: Into<String>,
  V: Into<String>,
{
  for (public_hex, private_hex) in entries {
    let private_hex = private_hex.into();
    if !private_hex.is_empty() {
      ring.insert(public_hex.into(), private_hex);
    }
  }
}

/// The public keys of the ring's still-blank (`""`) entries, in ring insertion
/// order. A provider iterates these, re-checking after each consult that the
/// entry is still blank (an earlier consult in the same pass may have filled it).
pub(crate) fn blank_public_keys(ring: &Ring) -> Vec<String> {
  ring
    .iter()
    .filter(|(_, v)| v.is_empty())
    .map(|(k, _)| k.clone())
    .collect()
}

pub mod keychain;

mod gating;

pub use gating::{
  backend_available, build_providers, ci_vendor_detected, ci_vendor_detected_from_env,
  use_keychain, ProviderGating, CI_VENDOR_VARS,
};
