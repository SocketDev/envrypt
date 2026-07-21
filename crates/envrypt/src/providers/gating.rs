//! Provider assembly and the keychain gating decision.
//!
//! [`build_providers`] decides WHICH providers fill the ring blanks and in what
//! order, then hands the list to the keyring. The keychain is the only provider.
//!
//! ## The gate
//! The keychain is a first-class provider on all three OSes (macOS/Windows/
//! Linux). [`use_keychain`] enables it when:
//!   * [`backend_available`] holds — a backend ships for `darwin`/`win32`/
//!     `linux`. A missing helper binary is handled at runtime by the provider
//!     yielding `{}`, not by this gate;
//!   * no CI vendor is detected ([`CI_VENDOR_VARS`], the CI-relevant subset of
//!     `output/color_depth.rs`'s vendor vars);
//!   * the native/keychain-off flags are clear.
//!
//! Tty-interactivity is NOT a discriminator: an embedded library in a non-tty
//! local process must still use the keychain. "Resolve never blocks" comes from
//! the bounded [`Exec`](super::keychain::Exec) timeout, not from tty-gating. On a
//! headless or unanswerable prompt the timeout fires, the provider yields `{}`,
//! and the env path takes over.
//!
//! The consumer policy can override the gate result: `KeyPolicy::EnvOnly`
//! disables the keychain and `KeyPolicy::Custom` replaces the chain.

use std::time::Duration;

use super::keychain::KeychainProvider;
use super::KeyProvider;

/// The subset of options the provider gating reads. `native_off` folds together
/// the "no native" and "native = false" spellings; both turn the keychain off, so
/// a single set of booleans captures them.
#[derive(Debug, Clone, Default)]
pub struct ProviderGating {
  /// The keychain is turned off (either "no native" or "native = false").
  pub native_off: bool,
  /// The keychain is turned off by the explicit "no keychain" flag.
  pub no_keychain: bool,
}

/// The CI-vendor environment variables whose presence marks a CI context, where
/// the keychain auto-skips. Covers the bare `CI`/`CI_NAME` plus each per-vendor
/// flag from the color-depth vendor list (`output/color_depth.rs`). Presence
/// counts even when the value is empty.
pub const CI_VENDOR_VARS: &[&str] = &[
  "CI",
  "CI_NAME",
  "GITHUB_ACTIONS",
  "GITLAB_CI",
  "CIRCLECI",
  "BUILDKITE",
  "DRONE",
  "TRAVIS",
  "APPVEYOR",
  "TEAMCITY_VERSION",
  "TF_BUILD",
  "GITEA_ACTIONS",
  "AGENT_NAME",
];

/// Whether ANY [`CI_VENDOR_VARS`] entry is present, via an injected presence
/// probe so it stays pure and testable. `present(name)` reports whether the name
/// is set in the environment.
pub fn ci_vendor_detected(present: impl Fn(&str) -> bool) -> bool {
  CI_VENDOR_VARS.iter().any(|name| present(name))
}

/// [`ci_vendor_detected`] against the real process environment (presence via `var_os`, so
/// a present-but-empty or non-UTF-8 value still counts as present).
pub fn ci_vendor_detected_from_env() -> bool {
  ci_vendor_detected(|name| std::env::var_os(name).is_some())
}

/// Whether a keychain backend ships for `platform`: macOS `security`, Windows
/// Credential Manager (PowerShell), Linux Secret Service (`secret-tool`). Runtime
/// absence of the helper binary is NOT decided here; the provider yields `{}` and
/// resolution falls through to the env path.
pub fn backend_available(platform: &str) -> bool {
  matches!(platform, "darwin" | "win32" | "linux")
}

/// Whether to use the keychain: a backend exists for `platform` AND no CI vendor
/// is detected AND the native/keychain-off flags are clear. `ci_detected` comes
/// from [`ci_vendor_detected`].
pub fn use_keychain(gating: &ProviderGating, platform: &str, ci_detected: bool) -> bool {
  if !backend_available(platform) {
    return false;
  }
  if ci_detected {
    return false;
  }
  !gating.native_off && !gating.no_keychain
}

/// Assemble the ordered provider list for the two-phase keyring: the keychain
/// provider (bounded by `timeout`) when [`use_keychain`] holds, else empty.
///
/// `platform` and `ci_detected` are injected process facts, so tests stay
/// deterministic on any OS.
pub fn build_providers(
  gating: &ProviderGating,
  platform: &str,
  ci_detected: bool,
  timeout: Duration,
) -> Vec<Box<dyn KeyProvider>> {
  let mut providers: Vec<Box<dyn KeyProvider>> = Vec::new();
  if use_keychain(gating, platform, ci_detected) {
    providers.push(Box::new(KeychainProvider::system_with_timeout(timeout)));
  }
  providers
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::providers::keychain::DEFAULT_KEYCHAIN_TIMEOUT;

  fn gating() -> ProviderGating {
    ProviderGating::default()
  }

  // ---- decision table: OS backend present/absent × CI-vendor present/absent --------

  // The three supported OSes, off CI, with clear flags → keychain enabled.
  #[test]
  fn use_keychain_enabled_on_supported_os_off_ci() {
    for platform in ["darwin", "win32", "linux"] {
      assert!(
        use_keychain(&gating(), platform, false),
        "keychain should be enabled on {platform} off CI"
      );
    }
  }

  // A CI vendor detected → keychain disabled on every supported OS (env path takes over).
  #[test]
  fn use_keychain_disabled_under_ci_on_every_os() {
    for platform in ["darwin", "win32", "linux"] {
      assert!(
        !use_keychain(&gating(), platform, true),
        "keychain must auto-skip under CI on {platform}"
      );
    }
  }

  // No shipped backend for the OS → disabled regardless of CI.
  #[test]
  fn use_keychain_disabled_on_unsupported_os() {
    assert!(!use_keychain(&gating(), "freebsd", false));
    assert!(!use_keychain(&gating(), "aix", false));
    assert!(!use_keychain(&gating(), "freebsd", true));
  }

  // Consumer flags override the gate (KeyPolicy::EnvOnly maps to these downstream).
  #[test]
  fn use_keychain_honors_off_flags() {
    let native_off = ProviderGating {
      native_off: true,
      ..Default::default()
    };
    assert!(!use_keychain(&native_off, "darwin", false));
    assert!(!use_keychain(&native_off, "linux", false));
    let no_keychain = ProviderGating {
      no_keychain: true,
      ..Default::default()
    };
    assert!(!use_keychain(&no_keychain, "win32", false));
  }

  // ---- CI-vendor detection --------------------------------------------------------

  #[test]
  fn ci_vendor_detected_matches_the_vendor_list() {
    // No vendor present → not CI.
    assert!(!ci_vendor_detected(|_| false));
    // Any single vendor present → CI. Covers the whole list.
    for vendor in CI_VENDOR_VARS {
      assert!(
        ci_vendor_detected(|name| name == *vendor),
        "{vendor} should mark a CI context"
      );
    }
    // A non-CI env var does not trip detection.
    assert!(!ci_vendor_detected(|name| name == "HOME"));
  }

  // ---- build_providers threads the gate + the timeout -----------------------------

  #[test]
  fn build_providers_matrix() {
    let t = DEFAULT_KEYCHAIN_TIMEOUT;
    // Supported OS, off CI → one provider.
    for platform in ["darwin", "win32", "linux"] {
      assert_eq!(
        build_providers(&gating(), platform, false, t).len(),
        1,
        "{platform} off CI → keychain present"
      );
    }
    // Under CI → none, on every OS.
    for platform in ["darwin", "win32", "linux"] {
      assert!(build_providers(&gating(), platform, true, t).is_empty());
    }
    // Unsupported OS → none.
    assert!(build_providers(&gating(), "freebsd", false, t).is_empty());
    // native off → none.
    let native_off = ProviderGating {
      native_off: true,
      ..Default::default()
    };
    assert!(build_providers(&native_off, "darwin", false, t).is_empty());
  }
}
