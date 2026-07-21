//! Dev-only test harness for the envrypt workspace.
//!
//! Consumed strictly as a `dev-dependency`. Real-fs, real-process, and scoped-env
//! test doubles:
//!
//! * [`EnvGuard`] — scoped, RAII-restored environment-variable mutation.
//! * [`CwdGuard`] — scoped, RAII-restored current-directory change.
//! * [`shim_bin`] — PATH-shim executables for child-process stubs.
//! * [`LoggerCapture`] — sink capture for the injected logger writers.
//! * [`standard_env`] — the base env for every integration run.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

/// A poison-tolerant lock: parallel test threads share one process env / cwd, so
/// mutations must be serialized. Recovering from poisoning keeps one panicking test
/// from cascading into every other env/cwd test.
fn lock<'a>(m: &'a Mutex<()>) -> MutexGuard<'a, ()> {
  m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// EnvGuard
// ---------------------------------------------------------------------------

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Scoped environment-variable mutation with RAII restore.
///
/// Holds a process-global lock for its whole lifetime so no two guards mutate the
/// environment concurrently (raw `std::env::set_var` across parallel test threads is
/// a data race). On drop, every touched key is restored to the value it held when the
/// guard first touched it — including "was unset".
///
/// # Deadlock hazard
/// The lock is NOT reentrant. While an `EnvGuard` is alive on a thread, that thread
/// must not call [`standard_env`] or construct a second `EnvGuard` — both acquire the
/// same lock and will deadlock. Call `standard_env()` first, then create the guard.
pub struct EnvGuard {
  _lock: MutexGuard<'static, ()>,
  saved: Vec<(OsString, Option<OsString>)>,
}

impl EnvGuard {
  /// Acquire the global env lock. No variables are changed until [`set`](Self::set)
  /// / [`remove`](Self::remove) is called.
  pub fn new() -> Self {
    EnvGuard {
      _lock: lock(&ENV_LOCK),
      saved: Vec::new(),
    }
  }

  /// Set `key=val`, remembering the prior value for restore.
  pub fn set<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, val: V) -> &mut Self {
    self.remember(key.as_ref());
    std::env::set_var(key, val);
    self
  }

  /// Unset `key`, remembering the prior value for restore.
  pub fn remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Self {
    self.remember(key.as_ref());
    std::env::remove_var(key);
    self
  }

  fn remember(&mut self, key: &OsStr) {
    if !self.saved.iter().any(|(k, _)| k == key) {
      self.saved.push((key.to_os_string(), std::env::var_os(key)));
    }
  }
}

impl Default for EnvGuard {
  fn default() -> Self {
    Self::new()
  }
}

impl Drop for EnvGuard {
  fn drop(&mut self) {
    // Restore in reverse touch-order so the earliest snapshot wins.
    for (key, prior) in self.saved.drain(..).rev() {
      match prior {
        Some(val) => std::env::set_var(&key, val),
        None => std::env::remove_var(&key),
      }
    }
  }
}

// ---------------------------------------------------------------------------
// CwdGuard
// ---------------------------------------------------------------------------

static CWD_LOCK: Mutex<()> = Mutex::new(());

/// Scoped current-directory change with RAII restore. Prefer APIs that take a base
/// dir; use this only where cwd is contract (e.g. a project name derived from
/// `basename(cwd)`). Integration tests use `Command::current_dir`.
pub struct CwdGuard {
  _lock: MutexGuard<'static, ()>,
  original: PathBuf,
}

impl CwdGuard {
  /// Change the process cwd to `dir`, restoring the previous cwd on drop.
  pub fn change_to<P: AsRef<Path>>(dir: P) -> io::Result<Self> {
    let guard = lock(&CWD_LOCK);
    let original = std::env::current_dir()?;
    std::env::set_current_dir(dir)?;
    Ok(CwdGuard {
      _lock: guard,
      original,
    })
  }
}

impl Drop for CwdGuard {
  fn drop(&mut self) {
    let _ = std::env::set_current_dir(&self.original);
  }
}

// ---------------------------------------------------------------------------
// shim_bin
// ---------------------------------------------------------------------------

/// Write an executable shim named `name` running `script` into `dir`, returning its
/// path. On Unix a `#!/bin/sh` script with mode 0755; on Windows a `<name>.cmd` batch
/// file. Prepend `dir` to a child's `PATH` to intercept `git`, `gitleaks`, keychain
/// helpers, etc. Callers embed argv/env/cwd recording in `script` when they need to
/// assert it.
pub fn shim_bin(dir: &Path, name: &str, script: &str) -> io::Result<PathBuf> {
  #[cfg(not(windows))]
  let path = {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{script}\n"))?;
    let mut perms = std::fs::metadata(&path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms)?;
    path
  };
  #[cfg(windows)]
  let path = {
    let path = dir.join(format!("{name}.cmd"));
    let body = script.replace('\n', "\r\n");
    std::fs::write(&path, format!("@echo off\r\n{body}\r\n"))?;
    path
  };
  Ok(path)
}

// ---------------------------------------------------------------------------
// LoggerCapture
// ---------------------------------------------------------------------------

/// A shared, cloneable byte sink that implements [`Write`]. The logger writes through
/// two injected `Box<dyn Write>` handles; tests hand it clones of these.
#[derive(Clone, Default)]
pub struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
  /// A snapshot of the bytes written so far.
  pub fn contents(&self) -> Vec<u8> {
    self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
  }
}

impl Write for SharedBuf {
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    self
      .0
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .extend_from_slice(buf);
    Ok(buf.len())
  }

  fn flush(&mut self) -> io::Result<()> {
    Ok(())
  }
}

/// Captures the logger's stdout/stderr streams into shared buffers and exposes them as
/// strings or lines. Tap assertions like `errorStub.calledWith("…")` become
/// string-equality checks against [`stderr_lines`](Self::stderr_lines).
#[derive(Clone, Default)]
pub struct LoggerCapture {
  out: SharedBuf,
  err: SharedBuf,
}

impl LoggerCapture {
  pub fn new() -> Self {
    Self::default()
  }

  /// A writer clone for the stdout stream (feed to the logger's stdout handle).
  pub fn stdout_writer(&self) -> SharedBuf {
    self.out.clone()
  }

  /// A writer clone for the stderr stream (feed to the logger's stderr handle).
  pub fn stderr_writer(&self) -> SharedBuf {
    self.err.clone()
  }

  pub fn stdout(&self) -> String {
    String::from_utf8_lossy(&self.out.contents()).into_owned()
  }

  pub fn stderr(&self) -> String {
    String::from_utf8_lossy(&self.err.contents()).into_owned()
  }

  /// Captured stdout split into lines, dropping the single trailing empty line that a
  /// final `\n` produces (the tap suite asserts line-by-line).
  pub fn stdout_lines(&self) -> Vec<String> {
    split_lines(&self.stdout())
  }

  pub fn stderr_lines(&self) -> Vec<String> {
    split_lines(&self.stderr())
  }
}

fn split_lines(s: &str) -> Vec<String> {
  let mut lines: Vec<String> = s.split('\n').map(String::from).collect();
  if lines.last().is_some_and(|l| l.is_empty()) {
    lines.pop();
  }
  lines
}

// ---------------------------------------------------------------------------
// standard_env
// ---------------------------------------------------------------------------

/// The base environment for every child-process test execution.
///
/// Holds a fresh config tempdir alive for as long as the value lives; drop it only
/// after the child process has exited. Feed it to a command with
/// `cmd.env_clear().envs(&env)`.
pub struct StandardEnv {
  config_dir: tempfile::TempDir,
  vars: Vec<(OsString, OsString)>,
}

impl StandardEnv {
  /// The fresh config directory (isolates the device store), seeded into
  /// `ENVRYPT_CONFIG`.
  pub fn config_dir(&self) -> &Path {
    self.config_dir.path()
  }

  /// The environment pairs: `PATH` and `ENVRYPT_CONFIG`.
  pub fn vars(&self) -> &[(OsString, OsString)] {
    &self.vars
  }
}

impl<'a> IntoIterator for &'a StandardEnv {
  type Item = (&'a OsString, &'a OsString);
  type IntoIter = std::iter::Map<
    std::slice::Iter<'a, (OsString, OsString)>,
    fn(&'a (OsString, OsString)) -> (&'a OsString, &'a OsString),
  >;

  fn into_iter(self) -> Self::IntoIter {
    self.vars.iter().map(|(k, v)| (k, v))
  }
}

/// Build the standard test env: `{PATH = host PATH, ENVRYPT_CONFIG = <fresh mkdtemp>}`.
///
/// `ENVRYPT_CONFIG` isolates the device store to a fresh tempdir per test. Empty
/// otherwise ⇒ piped, non-TTY stdio ⇒ color depth 1 ⇒ zero ANSI codes.
///
/// # Deadlock hazard
/// Briefly acquires the same global lock [`EnvGuard`] holds for its lifetime — never
/// call this while an `EnvGuard` is alive on the current thread (non-reentrant mutex;
/// it will deadlock). Call `standard_env()` first, then create the guard.
///
/// # Panics
/// If a temp directory cannot be created (a broken test host).
pub fn standard_env() -> StandardEnv {
  let config_dir =
    tempfile::tempdir().expect("test-support: failed to create ENVRYPT_CONFIG tempdir");
  // Read PATH under the env lock: a concurrent `EnvGuard` mutation on another thread
  // could otherwise reallocate the process `environ` array mid-read.
  let path = {
    let _l = lock(&ENV_LOCK);
    std::env::var_os("PATH").unwrap_or_default()
  };
  let cfg = config_dir.path().as_os_str().to_os_string();
  let vars = vec![
    (OsString::from("PATH"), path),
    (OsString::from("ENVRYPT_CONFIG"), cfg),
  ];
  StandardEnv { config_dir, vars }
}

// ---------------------------------------------------------------------------
// fixture_path
// ---------------------------------------------------------------------------

/// Absolute path to `conformance/fixtures/<rel>`. This only computes the path; it does
/// not require the file to exist.
pub fn fixture_path(rel: &str) -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("../../conformance/fixtures")
    .join(rel)
}

// ---------------------------------------------------------------------------
// lock_value_v1 — the v1 `locked:` WRITER (interop vector generation)
// ---------------------------------------------------------------------------

/// Produce a **v1** `locked:` value, byte-for-byte per
/// `docs/envrypt/crypto-formats.md` §2:
///
/// ```text
/// locked:<public_key_hex>:<base64url(payload)>        (base64url, no padding)
/// payload = 0x01 || salt(16) || iv(12) || tag(16) || ciphertext
/// key     = scrypt(passphrase, salt, N=2^14, r=8, p=1, dklen=32)
/// cipher  = AES-256-GCM(key, iv), 16-byte tag stored BEFORE the ciphertext
/// ```
///
/// Test-support only: the library ships the v1 READ path
/// (`envrypt::services::lock::unlock_value`); this writer exists so fresh v1
/// interop vectors can be minted forever in-repo. The interop tripwire
/// (`crates/envrypt/tests/interop_corpus.rs`) proves each freshly written value
/// unlocks through the shipped reader.
pub fn lock_value_v1(public_key_hex: &str, plaintext: &str, passphrase: &str) -> String {
  use aes_gcm::aead::consts::U12;
  use aes_gcm::aead::{Aead, KeyInit};
  use aes_gcm::aes::Aes256;
  use aes_gcm::AesGcm;
  use rand_core::{OsRng, RngCore};

  /// AES-256-GCM with the v1 lock's 12-byte IV.
  type Aes256Gcm12 = AesGcm<Aes256, U12>;

  let mut salt = [0u8; 16];
  OsRng.fill_bytes(&mut salt);
  let mut iv = [0u8; 12];
  OsRng.fill_bytes(&mut iv);

  // scrypt with Node's `scryptSync` defaults: N=2^14, r=8, p=1, 32-byte key.
  let params = scrypt::Params::new(14, 8, 1, 32).expect("valid scrypt params");
  let mut key = [0u8; 32];
  scrypt::scrypt(passphrase.as_bytes(), &salt, &params, &mut key)
    .expect("scrypt output length is 32");

  let cipher = Aes256Gcm12::new(&key.into());
  let ct_and_tag = cipher
    .encrypt(&iv.into(), plaintext.as_bytes())
    .expect("AES-GCM encryption of an in-memory buffer cannot fail");
  let (ciphertext, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);

  // version 0x01, then salt/iv, then the tag BEFORE the ciphertext.
  let mut payload = Vec::with_capacity(1 + 16 + 12 + 16 + ciphertext.len());
  payload.push(0x01);
  payload.extend_from_slice(&salt);
  payload.extend_from_slice(&iv);
  payload.extend_from_slice(tag);
  payload.extend_from_slice(ciphertext);

  format!("locked:{public_key_hex}:{}", base64url_encode(&payload))
}

/// Unpadded URL-safe base64 (Node `.toString('base64url')`) — the v1 `locked:`
/// payload encoding.
fn base64url_encode(bytes: &[u8]) -> String {
  const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
  let (chunks, rem) = bytes.as_chunks::<3>();
  for chunk in chunks {
    let acc = u32::from(chunk[0]) << 16 | u32::from(chunk[1]) << 8 | u32::from(chunk[2]);
    for shift in [18, 12, 6, 0] {
      out.push(B64URL[(acc >> shift & 0x3f) as usize] as char);
    }
  }
  match *rem {
    [a] => {
      let acc = u32::from(a) << 16;
      out.push(B64URL[(acc >> 18 & 0x3f) as usize] as char);
      out.push(B64URL[(acc >> 12 & 0x3f) as usize] as char);
    }
    [a, b] => {
      let acc = u32::from(a) << 16 | u32::from(b) << 8;
      out.push(B64URL[(acc >> 18 & 0x3f) as usize] as char);
      out.push(B64URL[(acc >> 12 & 0x3f) as usize] as char);
      out.push(B64URL[(acc >> 6 & 0x3f) as usize] as char);
    }
    _ => {}
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;

  // All raw env/cwd access in tests must hold the matching global lock — otherwise a
  // read here races an `EnvGuard`/`CwdGuard` mutation on another parallel test thread
  // (concurrent `setenv`/`getenv` corrupts the `environ` array). `EnvGuard::new()` and
  // `CwdGuard::change_to` take the lock themselves, so never nest these with a guard.
  fn with_env_lock<T>(f: impl FnOnce() -> T) -> T {
    let _l = lock(&ENV_LOCK);
    f()
  }
  fn with_cwd_lock<T>(f: impl FnOnce() -> T) -> T {
    let _l = lock(&CWD_LOCK);
    f()
  }

  #[test]
  fn env_guard_sets_then_restores_to_unset() {
    let key = "ENVRYPT_TESTSUPPORT_UNSET";
    {
      let mut g = EnvGuard::new();
      g.set(key, "value-1");
      assert_eq!(std::env::var(key).unwrap(), "value-1");
    }
    with_env_lock(|| assert!(std::env::var_os(key).is_none(), "must restore to unset"));
  }

  #[test]
  fn env_guard_remembers_first_touch_and_restores_prior() {
    let key = "ENVRYPT_TESTSUPPORT_PRIOR";
    with_env_lock(|| std::env::set_var(key, "original"));
    {
      let mut g = EnvGuard::new();
      g.set(key, "a");
      g.set(key, "b");
      assert_eq!(std::env::var(key).unwrap(), "b");
    }
    with_env_lock(|| {
      assert_eq!(
        std::env::var(key).unwrap(),
        "original",
        "restore reverts to first-touch value"
      );
      std::env::remove_var(key);
    });
  }

  #[test]
  fn env_guard_remove_then_restore() {
    let key = "ENVRYPT_TESTSUPPORT_REMOVE";
    with_env_lock(|| std::env::set_var(key, "here"));
    {
      let mut g = EnvGuard::new();
      g.remove(key);
      assert!(std::env::var_os(key).is_none());
    }
    with_env_lock(|| {
      assert_eq!(std::env::var(key).unwrap(), "here");
      std::env::remove_var(key);
    });
  }

  #[test]
  fn cwd_guard_changes_and_restores() {
    let before = with_cwd_lock(|| std::env::current_dir().unwrap());
    let tmp = tempfile::tempdir().unwrap();
    {
      let _g = CwdGuard::change_to(tmp.path()).unwrap();
      let now = std::env::current_dir().unwrap().canonicalize().unwrap();
      assert_eq!(now, tmp.path().canonicalize().unwrap());
    }
    let after = with_cwd_lock(|| std::env::current_dir().unwrap());
    assert_eq!(after, before);
  }

  #[cfg(not(windows))]
  #[test]
  fn shim_bin_is_executable_on_path() {
    let dir = tempfile::tempdir().unwrap();
    shim_bin(dir.path(), "mytool", "echo shimmed-$1").unwrap();

    let out = std::process::Command::new("mytool")
      .arg("arg")
      .env("PATH", dir.path())
      .output()
      .expect("shim should be found on PATH and be executable");
    assert!(out.status.success());
    assert_eq!(
      String::from_utf8_lossy(&out.stdout).trim_end(),
      "shimmed-arg"
    );
  }

  #[test]
  fn logger_capture_records_split_streams() {
    let cap = LoggerCapture::new();
    // The logger holds these as `Box<dyn Write>`.
    let mut out: Box<dyn Write> = Box::new(cap.stdout_writer());
    let mut err: Box<dyn Write> = Box::new(cap.stderr_writer());
    writeln!(out, "hello").unwrap();
    writeln!(out, "world").unwrap();
    writeln!(err, "☠ boom").unwrap();

    assert_eq!(cap.stdout_lines(), vec!["hello", "world"]);
    assert_eq!(cap.stderr_lines(), vec!["☠ boom"]);
    assert_eq!(cap.stdout(), "hello\nworld\n");
  }

  #[test]
  fn standard_env_shape() {
    let env = standard_env();
    let map: std::collections::HashMap<_, _> = env
      .vars()
      .iter()
      .map(|(k, v)| (k.clone(), v.clone()))
      .collect();

    assert!(map.contains_key(OsStr::new("PATH")));

    // The config var points at the fresh tempdir.
    let cfg = map.get(OsStr::new("ENVRYPT_CONFIG")).unwrap();
    assert_eq!(Path::new(cfg), env.config_dir());
    assert!(
      env.config_dir().is_dir(),
      "config dir must exist while the value lives"
    );

    // Exactly the two documented keys, nothing else.
    assert_eq!(env.vars().len(), 2);
  }

  #[test]
  fn fixture_path_is_absolute_under_conformance() {
    let p = fixture_path("root/.env");
    assert!(p.is_absolute());
    assert!(p.ends_with("conformance/fixtures/root/.env"));
  }
}
