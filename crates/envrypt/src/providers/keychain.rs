//! OS keychain key provider (macOS / Windows / Linux) behind the [`Exec`]
//! subprocess seam.
//!
//! A cross-OS provider on the resolve path:
//!
//!   * **macOS** — `/usr/bin/security find-generic-password` (Keychain Services);
//!   * **Windows** — Credential Manager via `powershell` + `CredRead` (P/Invoke);
//!   * **Linux** — Secret Service via `secret-tool lookup` (libsecret).
//!
//! Every backend goes through the same injected [`Exec`] seam, so the OS helper
//! is a plain subprocess with no D-Bus or async dependency. Tests inject canned
//! output on ANY OS, so all three argv/output shapes round-trip without a real
//! keychain.
//!
//! ## Hard invariants
//!
//!   1. **Non-blocking.** Every [`Exec`] call runs under a bounded timeout
//!      ([`DEFAULT_KEYCHAIN_TIMEOUT`], tunable via `LoadOptions.keychain_timeout`
//!      → [`super::build_providers`]). A library linked into an arbitrary host
//!      binary (writer ≠ reader) can trigger a **modal keychain-ACL dialog** on
//!      read; in a launchd/systemd/Docker/ssh/LSP context that dialog can never
//!      be answered. [`SystemExec`] therefore spawns the child and **waits with a
//!      deadline, killing it on timeout** so a prompt can never hang `load()`. On
//!      timeout the provider yields `{}` and resolution falls through to the
//!      env-var path.
//!   2. **Read-only.** `load()`/`config()` never mutate the keychain. Envrypt
//!      has no keychain write API because macOS `security(1)` requires a raw
//!      secret command argument; the resolve path only reads. See
//!      [`KeychainProvider::find`].
//!
//! ## ACL strategy
//! A caller selecting this opt-in policy accepts its platform's credential ACL.
//! A re-signed, rebuilt, or moved host binary may re-prompt; the bounded timeout
//! above keeps that prompt from ever hanging `load()`.

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use super::{blank_public_keys, merge_truthy, KeyProvider, ProviderError};
use crate::keyring::Ring;

/// The absolute macOS keychain binary path (cannot be PATH-shimmed).
pub const SECURITY_BIN: &str = "/usr/bin/security";
/// The Linux Secret Service helper (libsecret); resolved via PATH. Absent → `{}`.
pub const SECRET_TOOL_BIN: &str = "secret-tool";
/// The Windows shell used to reach Credential Manager (`CredRead`); resolved via PATH.
/// Absent → `{}`.
pub const POWERSHELL_BIN: &str = "powershell";

/// The keychain service name every read and write is keyed under.
pub const SERVICE: &str = "envrypt";

/// Default per-subprocess deadline for every keychain [`Exec`] call. Kept short
/// so a modal-dialog hang fails open to the env path quickly; tunable end-to-end
/// via `LoadOptions.keychain_timeout` → [`super::build_providers`].
pub const DEFAULT_KEYCHAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Poll granularity of the [`SystemExec`] spawn-wait loop. Small enough that a completed
/// subprocess is reaped promptly; large enough to avoid a busy spin.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// A subprocess runner **bounded by a deadline**. The provider only ever runs a
/// fixed helper (`security`/`secret-tool`/`powershell`); a trait lets tests
/// inject canned output on any OS.
///
/// A spawn failure, a non-zero exit, OR a timeout all surface as "no key": the
/// caller checks `status.success()` and treats an `Err` (spawn failure or
/// deadline) the same as an unsuccessful exit. `timeout` bounds the wall-clock
/// the call may take, and an impl MUST return within roughly that bound.
pub trait Exec {
  fn exec_file(&self, path: &str, args: &[&str], timeout: Duration) -> std::io::Result<Output>;
}

/// Production [`Exec`]: spawns the helper, then **waits with a deadline, killing
/// the child on timeout**. Captures stdout and discards stderr. A timeout
/// surfaces as [`std::io::ErrorKind::TimedOut`], which the provider treats as
/// `{}`.
pub struct SystemExec;

impl Exec for SystemExec {
  fn exec_file(&self, path: &str, args: &[&str], timeout: Duration) -> std::io::Result<Output> {
    let mut child = Command::new(path)
      .args(args)
      .stdin(Stdio::null())
      .stdout(Stdio::piped())
      .stderr(Stdio::null())
      .spawn()?;

    // spawn-wait-with-deadline: poll `try_wait` until the child exits or the deadline
    // fires, then kill. The helper output is tiny (a single key), well under the pipe
    // buffer, so reading stdout after exit cannot deadlock the loop.
    let deadline = Instant::now() + timeout;
    loop {
      match child.try_wait()? {
        Some(status) => {
          let mut stdout = Vec::new();
          if let Some(mut out) = child.stdout.take() {
            let _ = out.read_to_end(&mut stdout);
          }
          return Ok(Output {
            status,
            stdout,
            stderr: Vec::new(),
          });
        }
        None => {
          if Instant::now() >= deadline {
            // The child may be blocked on a modal keychain prompt
            // that can never be answered here; kill it and fail open.
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
              std::io::ErrorKind::TimedOut,
              "keychain subprocess exceeded its deadline",
            ));
          }
          std::thread::sleep(POLL_INTERVAL);
        }
      }
    }
  }
}

/// The read command (helper binary + argv) for `platform`'s keychain backend,
/// keyed by `service` + `account` (the compressed public-key hex). Returns `None`
/// when no backend ships for the platform; the provider then execs nothing and
/// yields `{}` (env fall-through). The resolve path only reads.
fn read_command(
  platform: &str,
  service: &str,
  account: &str,
) -> Option<(&'static str, Vec<String>)> {
  match platform {
    // macOS Keychain Services (`security find-generic-password -s <svc> -a <acct> -w`).
    "darwin" => Some((
      SECURITY_BIN,
      vec![
        "find-generic-password".into(),
        "-s".into(),
        service.into(),
        "-a".into(),
        account.into(),
        "-w".into(),
      ],
    )),
    // Linux Secret Service (`secret-tool lookup service <svc> account <acct>`). The
    // secret is printed to stdout with no trailing newline; exit 1 when absent.
    "linux" => Some((
      SECRET_TOOL_BIN,
      vec![
        "lookup".into(),
        "service".into(),
        service.into(),
        "account".into(),
        account.into(),
      ],
    )),
    // Windows Credential Manager via PowerShell + CredRead. The generic credential is
    // keyed by target name `<service>:<account>`; the script prints the stored blob.
    "win32" => Some((POWERSHELL_BIN, windows_read_args(service, account))),
    _ => None,
  }
}

/// `powershell -NoProfile -NonInteractive -Command <script>` where `<script>` reads the
/// Credential Manager generic credential `<service>:<account>` via a `CredRead` P/Invoke
/// and writes the stored secret to stdout (empty when absent → `{}`).
///
/// The target/account is compressed-pubkey hex (`[0-9a-f]`); single quotes are
/// doubled so the value cannot break out of the PowerShell single-quoted string.
/// CI round-trips the argv/output shape via an injected [`Exec`], so no real
/// Credential Manager is needed.
fn windows_read_args(service: &str, account: &str) -> Vec<String> {
  let target = format!("{service}:{account}").replace('\'', "''");
  let script = WINDOWS_CREDREAD_TEMPLATE.replace(WINDOWS_TARGET_PLACEHOLDER, &target);
  vec![
    "-NoProfile".into(),
    "-NonInteractive".into(),
    "-Command".into(),
    script,
  ]
}

/// Placeholder swapped for the single-quoted target name in [`WINDOWS_CREDREAD_TEMPLATE`].
const WINDOWS_TARGET_PLACEHOLDER: &str = "__ENVRYPT_TARGET__";

/// PowerShell `CredRead` reader for a generic Windows credential. Kept as a template
/// (placeholder rather than `format!`) so the embedded C#/PowerShell braces need no
/// escaping. Prints the credential blob (decoded as UTF-16LE, matching the provisioning
/// write) to stdout; prints nothing when the credential is absent.
const WINDOWS_CREDREAD_TEMPLATE: &str = "\
$ErrorActionPreference='Stop';\
$sig=@'
using System;
using System.Runtime.InteropServices;
public class EnvryptCred {
  [StructLayout(LayoutKind.Sequential)]
  public struct CREDENTIAL {
    public uint Flags; public uint Type; public IntPtr TargetName; public IntPtr Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public uint CredentialBlobSize; public IntPtr CredentialBlob; public uint Persist;
    public uint AttributeCount; public IntPtr Attributes; public IntPtr TargetAlias; public IntPtr UserName;
  }
  [DllImport(\"advapi32\", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);
  [DllImport(\"advapi32\")] public static extern void CredFree(IntPtr cred);
  public static string Read(string target) {
    IntPtr p;
    if (!CredRead(target, 1, 0, out p)) { return \"\"; }
    try {
      CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
      if (c.CredentialBlobSize == 0) { return \"\"; }
      byte[] b = new byte[c.CredentialBlobSize];
      Marshal.Copy(c.CredentialBlob, b, 0, (int)c.CredentialBlobSize);
      return System.Text.Encoding.Unicode.GetString(b);
    } finally { CredFree(p); }
  }
}
'@;\
Add-Type -TypeDefinition $sig | Out-Null;\
[Console]::Out.Write([EnvryptCred]::Read('__ENVRYPT_TARGET__'))";

/// The OS keychain provider (behind an injected [`Exec`]). `platform` selects the
/// backend (`darwin`/`win32`/`linux`); `timeout` bounds every subprocess.
pub struct KeychainProvider {
  exec: Box<dyn Exec>,
  platform: String,
  timeout: Duration,
}

impl KeychainProvider {
  /// Production provider: [`SystemExec`] + the real host platform + the default timeout.
  pub fn system() -> Self {
    Self::system_with_timeout(DEFAULT_KEYCHAIN_TIMEOUT)
  }

  /// Production provider with an explicit deadline
  /// (`LoadOptions.keychain_timeout` threads through here).
  pub fn system_with_timeout(timeout: Duration) -> Self {
    Self {
      exec: Box::new(SystemExec),
      platform: node_platform().to_string(),
      timeout,
    }
  }

  /// Provider over an injected [`Exec`] and explicit platform (test seam; the default
  /// timeout). Exercises any of `darwin`/`win32`/`linux` on any host OS.
  pub fn with_exec(exec: Box<dyn Exec>, platform: impl Into<String>) -> Self {
    Self::with_exec_timeout(exec, platform, DEFAULT_KEYCHAIN_TIMEOUT)
  }

  /// Provider over an injected [`Exec`], explicit platform, and explicit timeout (test
  /// seam for the bounded-timeout behavior).
  pub fn with_exec_timeout(
    exec: Box<dyn Exec>,
    platform: impl Into<String>,
    timeout: Duration,
  ) -> Self {
    Self {
      exec,
      platform: platform.into(),
      timeout,
    }
  }

  /// Read the private key for `public_key_hex` from the [`SERVICE`] keychain
  /// entry, via the current platform's backend. Returns `None` on an
  /// unsupported platform (no exec), a spawn/exit failure, a timeout, or empty
  /// output.
  ///
  /// **Read-only:** `load()`/`config()` never mutate the keychain.
  fn find(&self, public_key_hex: &str) -> Option<String> {
    let (bin, args) = read_command(&self.platform, SERVICE, public_key_hex)?;
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = self.exec.exec_file(bin, &argv, self.timeout).ok()?;
    if !output.status.success() {
      return None;
    }
    let private_key_hex = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if private_key_hex.is_empty() {
      None
    } else {
      Some(private_key_hex)
    }
  }
}

impl KeyProvider for KeychainProvider {
  fn lookup(&self, ring: &mut Ring, _on_status: &mut dyn FnMut(&str)) -> Result<(), ProviderError> {
    // Consult the keychain once per still-blank public key, skipping any
    // filled by an earlier consult in this pass.
    for public_hex in blank_public_keys(ring) {
      if ring.get(&public_hex).is_some_and(|v| !v.is_empty()) {
        // Unreachable through this provider (each find fills only its own key);
        // guards a future multi-key provider (providers/mod.rs merge_truthy).
        continue;
      }
      if let Some(private_hex) = self.find(&public_hex) {
        merge_truthy(ring, [(public_hex, private_hex)]);
      }
    }
    // The keychain provider never errors: a timeout or absent helper yields
    // `{}` and resolution falls through to the env path.
    Ok(())
  }
}

/// The platform string the backend is selected by: macOS → `darwin`, Windows →
/// `win32`, else the Rust OS name. Public so the resolve-command call sites can
/// pass it to [`super::use_keychain`] when assembling the provider list.
pub fn node_platform() -> &'static str {
  platform_for_os(std::env::consts::OS)
}

/// Map a Rust OS name to its platform string. Split from [`node_platform`] so a
/// test drives every arm on any host; `node_platform` reads the build's OS
/// constant, which fixes one arm per target.
fn platform_for_os(os: &'static str) -> &'static str {
  match os {
    "macos" => "darwin",
    "windows" => "win32",
    other => other,
  }
}

/// Build a cross-platform `ExitStatus` carrying `code` as the process exit code,
/// for the `Exec` test fakes. `std::process::ExitStatus` has no portable public
/// constructor — `ExitStatusExt::from_raw` takes a unix wait status but a windows
/// exit code — so the fakes route through this one spot instead of a unix-only
/// `from_raw` that fails to compile on windows.
#[cfg(test)]
pub(crate) fn exit_status_from_code(code: i32) -> std::process::ExitStatus {
  #[cfg(unix)]
  use std::os::unix::process::ExitStatusExt;
  #[cfg(windows)]
  use std::os::windows::process::ExitStatusExt;
  #[cfg(unix)]
  let raw = (code & 0xff) << 8;
  #[cfg(windows)]
  let raw = code as u32;
  std::process::ExitStatus::from_raw(raw)
}

#[cfg(test)]
mod tests {
  // Inject an `Exec` fake and a platform string so all three OS backends run
  // on any host OS.
  use super::*;
  use std::cell::RefCell;
  use std::process::Output;
  use std::rc::Rc;

  #[test]
  fn platform_for_os_maps_every_arm() {
    assert_eq!(platform_for_os("macos"), "darwin");
    assert_eq!(platform_for_os("windows"), "win32");
    assert_eq!(platform_for_os("linux"), "linux");
  }

  #[derive(Default)]
  struct Recorded {
    /// (path, argv) of every exec, and the timeout it was called with.
    calls: Vec<(String, Vec<String>)>,
    timeouts: Vec<Duration>,
  }

  /// A fake `Exec` recording its calls (path, argv, timeout) and returning a canned
  /// exit/stdout. Honors the `Exec` bounded-timeout contract trivially (returns at once).
  struct FakeExec {
    recorded: Rc<RefCell<Recorded>>,
    status: i32,
    stdout: Vec<u8>,
  }

  impl Exec for FakeExec {
    fn exec_file(&self, path: &str, args: &[&str], timeout: Duration) -> std::io::Result<Output> {
      let mut rec = self.recorded.borrow_mut();
      rec.calls.push((
        path.to_string(),
        args.iter().map(|a| a.to_string()).collect(),
      ));
      rec.timeouts.push(timeout);
      Ok(Output {
        status: exit_status_from_code(self.status),
        stdout: self.stdout.clone(),
        stderr: Vec::new(),
      })
    }
  }

  fn ring_with_blank(public_hex: &str) -> Ring {
    let mut ring = Ring::new();
    ring.insert(public_hex.to_string(), String::new());
    ring
  }

  // ---- macOS backend --------------------------------------------------------------

  // macOS: exact security(1) argv, trimmed stdout fills the blank, under the
  // default timeout.
  #[test]
  fn reads_keychain_on_darwin() {
    let recorded = Rc::new(RefCell::new(Recorded::default()));
    let exec = FakeExec {
      recorded: recorded.clone(),
      status: 0,
      stdout: b"private-key\n".to_vec(),
    };
    let provider = KeychainProvider::with_exec(Box::new(exec), "darwin");
    let mut ring = ring_with_blank("public-key");
    provider.lookup(&mut ring, &mut |_| {}).unwrap();
    assert_eq!(ring.get("public-key"), Some(&"private-key".to_string()));
    let rec = recorded.borrow();
    assert_eq!(rec.calls.len(), 1);
    assert_eq!(rec.calls[0].0, SECURITY_BIN);
    assert_eq!(
      rec.calls[0].1,
      vec![
        "find-generic-password",
        "-s",
        "envrypt",
        "-a",
        "public-key",
        "-w"
      ]
    );
    // Every Exec call carried the bounded timeout.
    assert_eq!(rec.timeouts, vec![DEFAULT_KEYCHAIN_TIMEOUT]);
  }

  // ---- Linux backend (secret-tool) ------------------------------------------------

  // secret-tool round-trip: `lookup service envrypt account <pub>`; no-newline stdout.
  #[test]
  fn reads_secret_service_on_linux() {
    let recorded = Rc::new(RefCell::new(Recorded::default()));
    let exec = FakeExec {
      recorded: recorded.clone(),
      status: 0,
      stdout: b"linux-priv".to_vec(), // secret-tool prints no trailing newline
    };
    let provider = KeychainProvider::with_exec(Box::new(exec), "linux");
    let mut ring = ring_with_blank("pubhex");
    provider.lookup(&mut ring, &mut |_| {}).unwrap();
    assert_eq!(ring.get("pubhex"), Some(&"linux-priv".to_string()));
    let rec = recorded.borrow();
    assert_eq!(rec.calls[0].0, SECRET_TOOL_BIN);
    assert_eq!(
      rec.calls[0].1,
      vec!["lookup", "service", "envrypt", "account", "pubhex"]
    );
  }

  // ---- Windows backend (PowerShell + CredRead) ------------------------------------

  // Windows round-trip: `powershell -NoProfile -NonInteractive -Command <script>` whose
  // script names the `envrypt:<pub>` target; canned stdout fills the ring.
  #[test]
  fn reads_credential_manager_on_win32() {
    let recorded = Rc::new(RefCell::new(Recorded::default()));
    let exec = FakeExec {
      recorded: recorded.clone(),
      status: 0,
      stdout: b"win-priv\r\n".to_vec(), // PowerShell may emit CRLF; trimmed
    };
    let provider = KeychainProvider::with_exec(Box::new(exec), "win32");
    let mut ring = ring_with_blank("abcd");
    provider.lookup(&mut ring, &mut |_| {}).unwrap();
    assert_eq!(ring.get("abcd"), Some(&"win-priv".to_string()));
    let rec = recorded.borrow();
    assert_eq!(rec.calls[0].0, POWERSHELL_BIN);
    let args = &rec.calls[0].1;
    assert_eq!(args[0], "-NoProfile");
    assert_eq!(args[1], "-NonInteractive");
    assert_eq!(args[2], "-Command");
    // The script targets the envrypt-service credential for this public key.
    assert!(args[3].contains("envrypt:abcd"), "script: {}", args[3]);
    assert!(args[3].contains("CredRead"));
  }

  // ---- unsupported platform -------------------------------------------------------

  // An OS with no shipped backend → no exec, ring stays blank (env fall-through).
  #[test]
  fn unsupported_platform_does_not_exec() {
    let recorded = Rc::new(RefCell::new(Recorded::default()));
    let exec = FakeExec {
      recorded: recorded.clone(),
      status: 0,
      stdout: b"unused\n".to_vec(),
    };
    let provider = KeychainProvider::with_exec(Box::new(exec), "freebsd");
    let mut ring = ring_with_blank("public-key");
    provider.lookup(&mut ring, &mut |_| {}).unwrap();
    assert_eq!(ring.get("public-key"), Some(&String::new()));
    assert_eq!(
      recorded.borrow().calls.len(),
      0,
      "no exec off a supported OS"
    );
  }

  // ---- single-service read + read-only --------------------------------------------

  /// A fake that misses every `find-generic-password` (exit 1) and records EVERY
  /// subcommand so a test can assert the resolve path issues reads only.
  struct MissExec {
    calls: Rc<RefCell<Vec<Vec<String>>>>,
  }
  impl Exec for MissExec {
    fn exec_file(&self, _path: &str, args: &[&str], _timeout: Duration) -> std::io::Result<Output> {
      let argv: Vec<String> = args.iter().map(|a| a.to_string()).collect();
      self.calls.borrow_mut().push(argv);
      Ok(Output {
        status: exit_status_from_code(1), // exit code 1: key absent
        stdout: Vec::new(),
        stderr: Vec::new(),
      })
    }
  }

  // A miss issues exactly ONE read, keyed to the `envrypt` service, and ZERO
  // writes — no `add-generic-password` on the resolve path (writes live in the
  // provisioning API).
  #[test]
  fn miss_issues_one_envrypt_read_and_no_write() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let provider = KeychainProvider::with_exec(
      Box::new(MissExec {
        calls: calls.clone(),
      }),
      "darwin",
    );
    let mut ring = ring_with_blank("pubhex");
    provider.lookup(&mut ring, &mut |_| {}).unwrap();

    // The miss leaves the blank blank (env fall-through).
    assert_eq!(ring.get("pubhex"), Some(&String::new()));
    let calls = calls.borrow();
    // Exactly one read, keyed to the envrypt service.
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0][..3], ["find-generic-password", "-s", "envrypt"]);
    // READ-ONLY: not a single write on the resolve path.
    assert!(
      calls.iter().all(|c| c[0] == "find-generic-password"),
      "resolve path must issue only reads, got: {calls:?}"
    );
  }

  // ---- failure modes → blank ------------------------------------------------------

  // A non-zero exit (key not found) → the blank stays blank.
  #[test]
  fn nonzero_exit_leaves_blank() {
    let recorded = Rc::new(RefCell::new(Recorded::default()));
    let exec = FakeExec {
      recorded,
      status: 1 << 8, // exit code 1 (wait-status encoding)
      stdout: Vec::new(),
    };
    let provider = KeychainProvider::with_exec(Box::new(exec), "darwin");
    let mut ring = ring_with_blank("public-key");
    provider.lookup(&mut ring, &mut |_| {}).unwrap();
    assert_eq!(ring.get("public-key"), Some(&String::new()));
  }

  // Empty (whitespace-only) stdout on success → blank stays blank.
  #[test]
  fn empty_stdout_leaves_blank() {
    let recorded = Rc::new(RefCell::new(Recorded::default()));
    let exec = FakeExec {
      recorded,
      status: 0,
      stdout: b"   \n".to_vec(),
    };
    let provider = KeychainProvider::with_exec(Box::new(exec), "darwin");
    let mut ring = ring_with_blank("public-key");
    provider.lookup(&mut ring, &mut |_| {}).unwrap();
    assert_eq!(ring.get("public-key"), Some(&String::new()));
  }

  // An already-filled ring entry is not consulted (blank-only iteration).
  #[test]
  fn filled_entry_not_consulted() {
    let recorded = Rc::new(RefCell::new(Recorded::default()));
    let exec = FakeExec {
      recorded: recorded.clone(),
      status: 0,
      stdout: b"other\n".to_vec(),
    };
    let provider = KeychainProvider::with_exec(Box::new(exec), "darwin");
    let mut ring = Ring::new();
    ring.insert("filled".to_string(), "already".to_string());
    provider.lookup(&mut ring, &mut |_| {}).unwrap();
    assert_eq!(ring.get("filled"), Some(&"already".to_string()));
    assert_eq!(recorded.borrow().calls.len(), 0);
  }

  // ---- bounded timeout, fail-open ------------------------------------------------

  /// A fake `Exec` modeling a subprocess blocked on an unanswerable modal keychain
  /// prompt: it sleeps the bounded `timeout` (never the full `block`) and returns
  /// [`std::io::ErrorKind::TimedOut`], the kill-at-deadline outcome [`SystemExec`]
  /// produces. The test then observes a wall-clock bound well under `block`.
  struct BlockingExec {
    block: Duration,
  }
  impl Exec for BlockingExec {
    fn exec_file(&self, _path: &str, _args: &[&str], timeout: Duration) -> std::io::Result<Output> {
      std::thread::sleep(timeout.min(self.block));
      Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "simulated modal-prompt hang, killed at the deadline",
      ))
    }
  }

  // A blocking keychain read fails OPEN: the provider yields `{}` (ring stays blank) and
  // returns within the timeout bound — never the full block — so `load()` cannot hang;
  // resolution then falls through to the env path (asserted below).
  #[test]
  fn blocking_exec_times_out_and_fails_open() {
    let timeout = Duration::from_millis(50);
    // A "hang" that would block for 30 s absent the deadline.
    let exec = BlockingExec {
      block: Duration::from_secs(30),
    };
    let provider = KeychainProvider::with_exec_timeout(Box::new(exec), "darwin", timeout);
    let mut ring = ring_with_blank("public-key");

    let start = Instant::now();
    provider.lookup(&mut ring, &mut |_| {}).unwrap();
    let elapsed = start.elapsed();

    // Fail-open: the blank was NOT filled by the keychain.
    assert_eq!(ring.get("public-key"), Some(&String::new()));
    // Bounded: returned far under the 30 s block (generous ceiling for slow CI).
    assert!(
      elapsed < Duration::from_secs(5),
      "resolve must not block on a modal prompt; took {elapsed:?}"
    );

    // Env fall-through: with the keychain blank, keyring_local resolves the key from
    // the process env (the CI path) — proving the timeout hands off to the env var.
    use crate::conventions::keynames::default_key_naming;
    use crate::crypto::keypair;
    use crate::keyring::{keyring_local, KeyringLocalOptions};
    let kp = keypair();
    let mut seed = Ring::new();
    seed.insert(kp.public_key.clone(), String::new());
    let process_env: indexmap::IndexMap<String, String> =
      [("ENVRYPT_PRIVATE_KEY".to_string(), kp.private_key.clone())]
        .into_iter()
        .collect();
    let mut resolved = keyring_local(&KeyringLocalOptions {
      process_env: &process_env,
      fk: vec![std::path::PathBuf::from("this-file-does-not-exist.keys")],
      seed_ring: seed,
      naming: default_key_naming(),
    });
    // The (blank) keychain provider does not fill it; the env key already did.
    provider.lookup(&mut resolved, &mut |_| {}).unwrap();
    assert_eq!(resolved.get(&kp.public_key), Some(&kp.private_key));
  }

  // The REAL production seam (`SystemExec`) genuinely bounds a hanging subprocess:
  // `/bin/sh -c 'sleep 30'` with a 250 ms deadline returns a TimedOut error well under
  // 30 s (spawn-wait-kill) — the actual production proof that a modal-prompt hang cannot
  // wedge `load()`. This test only needs the poll loop to OBSERVE the deadline (the
  // child never finishes early), so it stays robust under heavy parallel-workspace
  // load: a test that instead asserted "subprocess COMPLETES within N" would starve
  // under load. The generous 20 s ceiling tolerates a badly loaded CI. Unix-only
  // (needs `/bin/sh`); the same spawn-wait-kill logic runs on Windows, validated
  // there via the injected `Exec` path.
  #[test]
  #[cfg(unix)]
  fn system_exec_kills_a_real_hanging_subprocess() {
    let start = Instant::now();
    let result = SystemExec.exec_file("/bin/sh", &["-c", "sleep 30"], Duration::from_millis(250));
    let elapsed = start.elapsed();
    assert!(
      matches!(&result, Err(e) if e.kind() == std::io::ErrorKind::TimedOut),
      "expected a TimedOut error, got {result:?}"
    );
    assert!(
      elapsed < Duration::from_secs(20),
      "spawn-wait-kill must return near the deadline; took {elapsed:?}"
    );
  }
}
