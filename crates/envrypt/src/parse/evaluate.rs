//! `evaluate()` — command substitution.
//!
//! The contract:
//! * matches are collected up front with `/\$\(([^)]+(?:\)[^(]*)*)\)/g`, then
//!   reduced over the evolving string;
//! * each command runs through the platform shell (`/bin/sh -c` on POSIX,
//!   `%ComSpec% /d /s /c` on Windows) with a child env of exactly
//!   `{...processEnv, ...runningParsed}` (runningParsed wins; nothing else
//!   inherited);
//! * the child's stderr passes through to the parent's stderr (execSync default);
//! * stdout is chomped of trailing `[\r\n]+` only;
//! * the output replaces the first remaining occurrence of the match string, with
//!   JS `String.replace` `$`-pattern semantics live;
//! * a failure returns `COMMAND_SUBSTITUTION_FAILED` with the Node message
//!   embedded: `Command failed: <command>` plus `\n<stderr>` when stderr is
//!   non-empty, trimmed. parse() swallows this error.

use crate::errors::EnvryptError;
use crate::parse::expand::js_string_replace_first;
use indexmap::IndexMap;
use std::path::Path;
use std::sync::LazyLock;

// Shell-exec-only imports. Under `cfg(fuzzing)`, `exec_shell` is a deterministic
// stub that spawns nothing, so these are unused.
#[cfg(not(fuzzing))]
use crate::parse::scan::js_trim;
#[cfg(not(fuzzing))]
use std::io::Write;
#[cfg(not(fuzzing))]
use std::process::{Command, Stdio};

/// The command-substitution match regex: `/\$\(([^)]+(?:\)[^(]*)*)\)/g`.
static EVAL_RE: LazyLock<regex::Regex> =
  LazyLock::new(|| regex::Regex::new(r"\$\(([^)]+(?:\)[^(]*)*)\)").expect("EVAL regex compiles"));

/// Options for [`evaluate`].
#[derive(Clone, Copy, Debug)]
pub struct EvaluateOptions<'a> {
  pub process_env: &'a IndexMap<String, String>,
  pub running_parsed: &'a IndexMap<String, String>,
  /// Working directory for the child. `None` inherits the process cwd.
  pub cwd: Option<&'a Path>,
}

/// Runs command substitution on `value`, returning `COMMAND_SUBSTITUTION_FAILED`
/// on the first failing command.
pub fn evaluate(value: &str, opts: &EvaluateOptions) -> Result<String, EnvryptError> {
  // EVAL_RE cannot match without a literal `$(`.
  if memchr::memmem::find(value.as_bytes(), b"$(").is_none() {
    return Ok(value.to_string());
  }

  // Collect all matches up front from the original value, then reduce over the
  // evolving string.
  let matches: Vec<&str> = EVAL_RE.find_iter(value).map(|m| m.as_str()).collect();
  let mut result = value.to_string();
  for matched in matches {
    let command = &matched[2..matched.len() - 1]; // slice(2, -1)
    let output = exec_shell(command, opts)?;
    let chomped = chomp(&output);
    // Replace the first remaining occurrence; `$`-patterns in the command
    // output are live. A match already consumed by a previous replacement
    // leaves the string unchanged.
    if let Some(next) = js_string_replace_first(&result, matched, chomped) {
      result = next;
    }
  }
  Ok(result)
}

/// Chomps all trailing CR/LF from `s` (interior newlines stay).
fn chomp(s: &str) -> &str {
  s.trim_end_matches(['\r', '\n'])
}

/// Fuzz-only command-substitution stub (`--cfg fuzzing`; see
/// docs/envrypt/fuzzing.md). Fuzz bytes must never reach a shell, so each
/// `$(command)` resolves through this deterministic stub, which echoes the command
/// text back. The real `EVAL_RE` match, `chomp`, and `js_string_replace_first`
/// (`$`-pattern-live) machinery still runs over fuzz-controlled bytes while nothing
/// executes. Only cargo-fuzz sets `cfg(fuzzing)` (declared in this crate's
/// `check-cfg`); every other build compiles the real `exec_shell` below.
#[cfg(fuzzing)]
fn exec_shell(command: &str, _opts: &EvaluateOptions) -> Result<String, EnvryptError> {
  Ok(command.to_string())
}

/// One `execSync(command, {env})` equivalent: the platform shell, a fresh child
/// env, piped stdout, stderr captured and passed through to the parent's stderr
/// (execSync's default), and stdin closed.
#[cfg(not(fuzzing))]
fn exec_shell(command: &str, opts: &EvaluateOptions) -> Result<String, EnvryptError> {
  let mut cmd = shell_command(command);
  cmd.env_clear();
  for (k, v) in opts.process_env {
    cmd.env(k, v);
  }
  for (k, v) in opts.running_parsed {
    cmd.env(k, v); // runningParsed wins
  }
  if let Some(dir) = opts.cwd {
    cmd.current_dir(dir);
  }
  cmd
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

  let out = cmd
    .output()
    .map_err(|e| EnvryptError::command_substitution_failed(command, &e.to_string()))?;

  // execSync passes the child's stderr through to the parent terminal.
  if !out.stderr.is_empty() {
    let _ = std::io::stderr().write_all(&out.stderr);
  }

  if out.status.success() {
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
  } else {
    // Node message: `Command failed: <cmd>` + `\n<stderr>`, then trimmed.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let node_message = format!("Command failed: {command}\n{stderr}");
    Err(EnvryptError::command_substitution_failed(
      command,
      js_trim(&node_message),
    ))
  }
}

/// Node `execSync`'s shell selection: `/bin/sh -c <command>` on POSIX,
/// `%ComSpec% /d /s /c "<command>"` (verbatim args) on Windows.
#[cfg(all(unix, not(fuzzing)))]
fn shell_command(command: &str) -> Command {
  let mut cmd = Command::new("/bin/sh");
  cmd.arg("-c").arg(command);
  cmd
}

#[cfg(all(windows, not(fuzzing)))]
fn shell_command(command: &str) -> Command {
  use std::os::windows::process::CommandExt;
  let comspec = std::env::var_os("ComSpec").unwrap_or_else(|| "cmd.exe".into());
  let mut cmd = Command::new(comspec);
  cmd.raw_arg("/d").raw_arg("/s").raw_arg("/c");
  cmd.raw_arg(format!("\"{command}\""));
  cmd
}

// Under `--cfg fuzzing` the stub stands in for the shell, so these assert the
// stub contract. This module compiles only in a fuzzing-flagged test build
// (`RUSTFLAGS="--cfg fuzzing" cargo test`).
#[cfg(all(test, fuzzing))]
mod fuzzing_stub_tests {
  use super::*;

  #[test]
  fn command_substitution_is_a_deterministic_no_spawn_stub() {
    // Echoes the command text back, then `evaluate` chomps + string-replaces.
    let empty = IndexMap::new();
    let opts = EvaluateOptions {
      process_env: &empty,
      running_parsed: &empty,
      cwd: None,
    };
    // `$(echo hi)` under the stub => command "echo hi" replaces the match.
    assert_eq!(evaluate("$(echo hi)", &opts).unwrap(), "echo hi");
    // Deterministic + never errors (no COMMAND_SUBSTITUTION_FAILED path).
    assert_eq!(
      evaluate("$(anything at all)", &opts).unwrap(),
      "anything at all"
    );
    // Non-`$(` inputs are untouched by the memmem gate.
    assert_eq!(evaluate("plain", &opts).unwrap(), "plain");
  }
}

#[cfg(all(test, unix, not(fuzzing)))]
mod tests {
  // Pins command substitution, including the exact Node error-message
  // composition. POSIX-only; children use sh builtins (echo/printf/pwd) to stay
  // hermetic.
  use super::*;

  fn env(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    pairs
      .iter()
      .map(|(k, v)| (k.to_string(), v.to_string()))
      .collect()
  }

  fn eval(
    value: &str,
    process_env: &IndexMap<String, String>,
  ) -> Result<String, crate::errors::EnvryptError> {
    let empty = IndexMap::new();
    evaluate(
      value,
      &EvaluateOptions {
        process_env,
        running_parsed: &empty,
        cwd: None,
      },
    )
  }

  #[test]
  fn basic_substitution_chomps_trailing_newline() {
    assert_eq!(eval("$(echo hi)", &env(&[])).unwrap(), "hi");
    assert_eq!(
      eval("pre $(echo hi) post", &env(&[])).unwrap(),
      "pre hi post"
    );
  }

  #[test]
  fn chomp_removes_all_trailing_crlf_but_keeps_interior() {
    // Only trailing [\r\n]+ is removed; interior newlines stay.
    assert_eq!(eval("$(printf 'a\\nb\\n\\n')", &env(&[])).unwrap(), "a\nb");
    assert_eq!(eval("$(printf 'a\\r\\n')", &env(&[])).unwrap(), "a");
  }

  #[test]
  fn child_env_is_exactly_process_env_merged_with_running_parsed() {
    // Child env is {...processEnv, ...runningParsed}: runningParsed wins,
    // nothing else inherited.
    let pe = env(&[("X", "fromPE")]);
    let rp = env(&[("X", "fromRP")]);
    let got = evaluate(
      "$(echo $X)",
      &EvaluateOptions {
        process_env: &pe,
        running_parsed: &rp,
        cwd: None,
      },
    )
    .unwrap();
    assert_eq!(got, "fromRP");
    // A var in neither map is absent from the child env entirely.
    assert_eq!(eval("$(echo [$UNSET_VAR])", &env(&[])).unwrap(), "[]");
  }

  #[test]
  fn nested_substitution_is_one_outer_match() {
    // The regex treats `$(echo $(echo inner))` as one command; the shell
    // resolves the inner substitution.
    assert_eq!(eval("$(echo $(echo inner))", &env(&[])).unwrap(), "inner");
  }

  #[test]
  fn adjacent_matches() {
    // `$(echo a)($(echo b)` → `a(b`.
    assert_eq!(eval("$(echo a)($(echo b)", &env(&[])).unwrap(), "a(b");
  }

  #[test]
  fn empty_parens_never_match() {
    assert_eq!(eval("$()", &env(&[])).unwrap(), "$()");
  }

  #[test]
  fn duplicate_commands_run_twice_and_both_replaced() {
    assert_eq!(
      eval("$(echo hi) and $(echo hi)", &env(&[])).unwrap(),
      "hi and hi"
    );
  }

  #[test]
  fn cwd_is_the_child_working_directory() {
    let dir = tempfile::tempdir().unwrap();
    let canonical = dir.path().canonicalize().unwrap();
    let empty = IndexMap::new();
    let got = evaluate(
      "$(pwd)",
      &EvaluateOptions {
        process_env: &empty,
        running_parsed: &empty,
        cwd: Some(dir.path()),
      },
    )
    .unwrap();
    assert_eq!(
      std::path::Path::new(&got).canonicalize().unwrap(),
      canonical
    );
  }

  #[test]
  fn failure_error_is_verbatim() {
    // Expected message:
    // [COMMAND_SUBSTITUTION_FAILED] could not evaluate command 'exit 3': Command failed: exit 3
    let err = eval("$(exit 3)", &env(&[])).unwrap_err();
    assert_eq!(err.code(), Some("COMMAND_SUBSTITUTION_FAILED"));
    assert_eq!(
      err.message(),
      "[COMMAND_SUBSTITUTION_FAILED] could not evaluate command 'exit 3': Command failed: exit 3"
    );
    assert_eq!(
      err.help(),
      Some("fix: [https://github.com/SocketDev/envrypt/issues/532]")
    );
    assert_eq!(
            err.message_with_help(),
            "[COMMAND_SUBSTITUTION_FAILED] could not evaluate command 'exit 3': Command failed: exit 3. fix: [https://github.com/SocketDev/envrypt/issues/532]"
        );
  }

  #[test]
  fn failure_message_embeds_stderr() {
    // stderr is appended after a newline, then the whole Node message is
    // trimmed.
    let err = eval("$(echo err 1>&2; exit 2)", &env(&[])).unwrap_err();
    assert_eq!(
            err.message(),
            "[COMMAND_SUBSTITUTION_FAILED] could not evaluate command 'echo err 1>&2; exit 2': Command failed: echo err 1>&2; exit 2\nerr"
        );
  }

  #[test]
  fn output_dollar_patterns_are_live_in_replacement() {
    // Command output containing `$&` is interpreted by String.replace: the
    // matched text is reinserted, leaving the value unchanged.
    let input = "$(printf '%s' '$&')";
    assert_eq!(eval(input, &env(&[])).unwrap(), input);
  }
}
