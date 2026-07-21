//! The OS keychain provider through its public [`Exec`] seam. An embedder can inject
//! a subprocess runner and drive the macOS, Linux, and Windows backends on any host.
//! These tests pin the argv each backend issues, the fill and fail-open behavior, and
//! the bounded-timeout guard that keeps a modal prompt from hanging `load()`.
//!
//! Construction uses `ExitStatus::from_raw`, so the file runs on the Unix targets the
//! crate builds for (Linux and macOS).

#![cfg(unix)]

use std::cell::RefCell;
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};
use std::rc::Rc;
use std::time::{Duration, Instant};

use envrypt::keyring::Ring;
use envrypt::providers::keychain::{
  node_platform, Exec, KeychainProvider, SystemExec, DEFAULT_KEYCHAIN_TIMEOUT, POWERSHELL_BIN,
  SECRET_TOOL_BIN, SECURITY_BIN,
};
use envrypt::providers::KeyProvider;

type ExecCall = (String, Vec<String>, Duration);
type ExecCalls = Rc<RefCell<Vec<ExecCall>>>;

/// A fake `Exec` recording each (path, argv, timeout) and returning a canned
/// exit code plus stdout.
struct FakeExec {
  calls: ExecCalls,
  status: i32,
  stdout: Vec<u8>,
}

impl Exec for FakeExec {
  fn exec_file(&self, path: &str, args: &[&str], timeout: Duration) -> std::io::Result<Output> {
    self.calls.borrow_mut().push((
      path.to_string(),
      args.iter().map(|a| a.to_string()).collect(),
      timeout,
    ));
    Ok(Output {
      status: ExitStatus::from_raw(self.status),
      stdout: self.stdout.clone(),
      stderr: Vec::new(),
    })
  }
}

fn fake(status: i32, stdout: &[u8]) -> (FakeExec, ExecCalls) {
  let calls = Rc::new(RefCell::new(Vec::new()));
  (
    FakeExec {
      calls: calls.clone(),
      status,
      stdout: stdout.to_vec(),
    },
    calls,
  )
}

fn ring_with_blank(public_hex: &str) -> Ring {
  let mut ring = Ring::new();
  ring.insert(public_hex.to_string(), String::new());
  ring
}

// macOS: the `security` argv, trimmed stdout fills the blank, under the default timeout.
#[test]
fn darwin_backend_issues_security_argv_and_fills() {
  let (exec, calls) = fake(0, b"darwin-priv\n");
  let provider = KeychainProvider::with_exec(Box::new(exec), "darwin");
  let mut ring = ring_with_blank("pubhex");
  provider.lookup(&mut ring, &mut |_| {}).unwrap();

  assert_eq!(ring.get("pubhex"), Some(&"darwin-priv".to_string()));
  let calls = calls.borrow();
  assert_eq!(calls.len(), 1);
  assert_eq!(calls[0].0, SECURITY_BIN);
  assert_eq!(
    calls[0].1,
    vec![
      "find-generic-password",
      "-s",
      "envrypt",
      "-a",
      "pubhex",
      "-w"
    ]
  );
  assert_eq!(calls[0].2, DEFAULT_KEYCHAIN_TIMEOUT);
}

// Linux: `secret-tool lookup service envrypt account <pub>`; stdout has no newline.
#[test]
fn linux_backend_issues_secret_tool_argv_and_fills() {
  let (exec, calls) = fake(0, b"linux-priv");
  let provider = KeychainProvider::with_exec(Box::new(exec), "linux");
  let mut ring = ring_with_blank("pubhex");
  provider.lookup(&mut ring, &mut |_| {}).unwrap();

  assert_eq!(ring.get("pubhex"), Some(&"linux-priv".to_string()));
  let calls = calls.borrow();
  assert_eq!(calls[0].0, SECRET_TOOL_BIN);
  assert_eq!(
    calls[0].1,
    vec!["lookup", "service", "envrypt", "account", "pubhex"]
  );
}

// Windows: `powershell -NoProfile -NonInteractive -Command <script>` naming the
// `envrypt:<pub>` target; canned stdout (CRLF is trimmed) fills the ring.
#[test]
fn windows_backend_issues_powershell_credread() {
  let (exec, calls) = fake(0, b"win-priv\r\n");
  let provider = KeychainProvider::with_exec(Box::new(exec), "win32");
  let mut ring = ring_with_blank("abcd");
  provider.lookup(&mut ring, &mut |_| {}).unwrap();

  assert_eq!(ring.get("abcd"), Some(&"win-priv".to_string()));
  let calls = calls.borrow();
  assert_eq!(calls[0].0, POWERSHELL_BIN);
  let args = &calls[0].1;
  assert_eq!(&args[..3], ["-NoProfile", "-NonInteractive", "-Command"]);
  assert!(args[3].contains("envrypt:abcd"), "script: {}", args[3]);
  assert!(args[3].contains("CredRead"));
}

// An OS with no shipped backend runs nothing and leaves the ring blank.
#[test]
fn unsupported_platform_execs_nothing() {
  let (exec, calls) = fake(0, b"unused\n");
  let provider = KeychainProvider::with_exec(Box::new(exec), "freebsd");
  let mut ring = ring_with_blank("pubhex");
  provider.lookup(&mut ring, &mut |_| {}).unwrap();

  assert_eq!(ring.get("pubhex"), Some(&String::new()));
  assert_eq!(calls.borrow().len(), 0);
}

// A miss (non-zero exit) and whitespace-only stdout both leave the blank blank; an
// already-filled entry is never consulted.
#[test]
fn miss_empty_and_filled_leave_the_ring_unchanged() {
  // exit 1: key absent.
  let (exec, _) = fake(1 << 8, b"");
  let provider = KeychainProvider::with_exec(Box::new(exec), "darwin");
  let mut ring = ring_with_blank("absent");
  provider.lookup(&mut ring, &mut |_| {}).unwrap();
  assert_eq!(ring.get("absent"), Some(&String::new()));

  // exit 0 but whitespace-only stdout.
  let (exec, _) = fake(0, b"   \n");
  let provider = KeychainProvider::with_exec(Box::new(exec), "darwin");
  let mut ring = ring_with_blank("blankout");
  provider.lookup(&mut ring, &mut |_| {}).unwrap();
  assert_eq!(ring.get("blankout"), Some(&String::new()));

  // A filled entry: no exec at all.
  let (exec, calls) = fake(0, b"other\n");
  let provider =
    KeychainProvider::with_exec_timeout(Box::new(exec), "darwin", Duration::from_millis(500));
  let mut ring = Ring::new();
  ring.insert("filled".to_string(), "already".to_string());
  provider.lookup(&mut ring, &mut |_| {}).unwrap();
  assert_eq!(ring.get("filled"), Some(&"already".to_string()));
  assert_eq!(calls.borrow().len(), 0);
}

// The production seam reaps a child that exits before the deadline and kills one that
// hangs past it, both without wedging the caller.
#[test]
fn system_exec_reaps_completion_and_bounds_a_hang() {
  // `/bin/echo` completes: Ok carrying the captured stdout.
  let done = SystemExec
    .exec_file("/bin/echo", &["envrypt-ok"], Duration::from_secs(5))
    .expect("echo completes within the deadline");
  assert!(done.status.success());
  assert_eq!(String::from_utf8_lossy(&done.stdout).trim(), "envrypt-ok");

  // `/bin/sh -c 'sleep 30'` never exits: killed at the 250 ms deadline, TimedOut.
  let start = Instant::now();
  let hung = SystemExec.exec_file("/bin/sh", &["-c", "sleep 30"], Duration::from_millis(250));
  assert!(
    matches!(&hung, Err(e) if e.kind() == std::io::ErrorKind::TimedOut),
    "expected TimedOut, got {hung:?}"
  );
  assert!(
    start.elapsed() < Duration::from_secs(20),
    "spawn-wait-kill must return near the deadline"
  );
}

// The production constructor wires `SystemExec` + the host platform + the default
// timeout, reads only, and leaves an unknown public key blank (the resolve path then
// falls through to the env var).
#[test]
fn system_provider_leaves_an_unknown_key_blank() {
  // The host backend must be one envrypt ships.
  assert!(
    matches!(node_platform(), "darwin" | "win32" | "linux"),
    "unexpected host backend: {}",
    node_platform()
  );

  let provider = KeychainProvider::system();
  let unknown = "0".repeat(64);
  let mut ring = ring_with_blank(&unknown);
  provider.lookup(&mut ring, &mut |_| {}).unwrap();
  assert_eq!(ring.get(&unknown), Some(&String::new()));
}
