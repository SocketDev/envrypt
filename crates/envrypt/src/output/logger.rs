//! The logger. Emits leveled, colored lines to stdout/stderr.
//!
//! Contract:
//!   * Levels: `error 0, infoerror 0, warn 1, success 2, successv 2, info 2,
//!     help 2, verbose 4, debug 5, silly 6`; default `info`. There is no `silly`
//!     emitter; it only raises the threshold.
//!   * `error`/`infoerror` → stderr, unconditionally (never level-gated). Every
//!     other level → stdout, emitted iff `value(level) <= threshold`. So `--quiet`
//!     (threshold `error`=0) still prints `error`/`infoerror`.
//!   * Prefixes/colors: `error` bold red `☠ `; `infoerror` gray, no prefix; `warn`
//!     orangered `⚠ `; `success` amber, no prefix; `successv` amber `⟐ ` +
//!     ` · <name>@<version>`; `info` gray; `help` dodgerblue; `verbose`/`debug`
//!     plum `┆ `.
//!   * `set_log_level` precedence: `debug` then `verbose` then `quiet` (→`error`)
//!     then `log_level`; on change logs `setting log level to: <level>` at debug
//!     unless quiet won.
//!
//! Color depth is injected: tests pass a fixed depth via [`Logger::new`]; the
//! real-stdio logger ([`Logger::stdio`]) resolves it lazily on the first styled
//! write, never at construction (see [`DepthSource`]). Every emit ends in `\n`.
//!
//! Object-message contract: a caller logging a structured value serializes it to
//! the byte-identical JSON string before calling the emitter. The API is `&str`-
//! only, so each structured payload's owner picks the serialization that preserves
//! its exact bytes:
//!   * the parsed env map — an insertion-ordered `string→string` map, serialized
//!     with compact, insertion-ordered `JSON.stringify` semantics (serde_json with
//!     `preserve_order`, no spaces);
//!   * a spawned child object — a runtime object;
//!   * a caught `Error` object — `JSON.stringify(new Error(..))` is `"{}"`.
//!
//! Callers that already hold a string pass it straight through.

use std::io::Write;

use super::colors::{bold, colorize, Color};

/// A log level. `Silly` has no emitter method; it exists only so
/// `set_level("silly")` raises the threshold to 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
  Error,
  Infoerror,
  Warn,
  Success,
  Successv,
  Info,
  Help,
  Verbose,
  Debug,
}

impl Level {
  /// Numeric threshold value.
  fn value(self) -> u8 {
    match self {
      Level::Error | Level::Infoerror => 0,
      Level::Warn => 1,
      Level::Success | Level::Successv | Level::Info | Level::Help => 2,
      Level::Verbose => 4,
      Level::Debug => 5,
    }
  }
}

/// Numeric value for a level name, including `silly` (threshold-only). `None` for
/// an unknown name; [`Logger::set_level`] silently ignores those.
fn level_value(name: &str) -> Option<u8> {
  Some(match name {
    "error" | "infoerror" => 0,
    "warn" => 1,
    "success" | "successv" | "info" | "help" => 2,
    "verbose" => 4,
    "debug" => 5,
    "silly" => 6,
    _ => return None,
  })
}

/// Options consumed by [`Logger::set_log_level`], mirroring the
/// `debug`/`verbose`/`quiet`/`log_level` flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogOptions {
  pub debug: bool,
  pub verbose: bool,
  pub quiet: bool,
  pub log_level: Option<String>,
}

/// How a [`Logger`] resolves its color depth. Lazy so the real-stdio logger probes
/// the environment only on the first styled write, never at construction.
enum DepthSource {
  /// A fixed, injected depth (tests and explicit callers).
  Fixed(u16),
  /// Resolve via [`super::color_depth::process_color_depth`] on demand. That value
  /// is a process-lifetime `LazyLock`, so the underlying env detection runs at most
  /// once, on the first emit that needs a depth.
  Process,
}

/// The envrypt logger. Writes through two injected sinks (stdout/stderr) so tests
/// can capture output via `test-support::LoggerCapture`.
pub struct Logger {
  /// Current numeric threshold (default `info` = 2).
  threshold: u8,
  /// Current level name (`logger.level` mirror).
  level_name: String,
  /// Logger name for the `successv` suffix (default `envrypt`).
  name: String,
  /// Logger version for the `successv` suffix (default package version).
  version: String,
  /// How color depth is resolved (fixed vs lazy — see [`DepthSource`]).
  depth: DepthSource,
  out: Box<dyn Write + Send>,
  err: Box<dyn Write + Send>,
}

impl Logger {
  /// Construct a logger writing to `out`/`err` at a fixed color `depth`. Defaults:
  /// level `info`, name `envrypt`, version = package version.
  pub fn new(out: Box<dyn Write + Send>, err: Box<dyn Write + Send>, depth: u16) -> Self {
    Self::with_depth_source(out, err, DepthSource::Fixed(depth))
  }

  /// A logger writing to the real process stdout/stderr. Color depth is resolved
  /// lazily on the first styled write (`DepthSource::Process`), so constructing the
  /// process logger never triggers env probing.
  pub fn stdio() -> Self {
    Self::with_depth_source(
      Box::new(std::io::stdout()),
      Box::new(std::io::stderr()),
      DepthSource::Process,
    )
  }

  fn with_depth_source(
    out: Box<dyn Write + Send>,
    err: Box<dyn Write + Send>,
    depth: DepthSource,
  ) -> Self {
    Logger {
      threshold: level_value("info").expect("info is a valid level"),
      level_name: "info".to_string(),
      name: "envrypt".to_string(),
      version: env!("CARGO_PKG_VERSION").to_string(),
      depth,
      out,
      err,
    }
  }

  /// The color depth for this write — the fixed value, or the lazily-resolved
  /// process depth (computed on first demand, never at construction).
  fn depth(&self) -> u16 {
    match self.depth {
      DepthSource::Fixed(depth) => depth,
      DepthSource::Process => super::color_depth::process_color_depth(),
    }
  }

  /// The current level name (`logger.level`).
  pub fn level(&self) -> &str {
    &self.level_name
  }

  /// Set the threshold iff `level` is a known name; unknown names are silently
  /// ignored.
  pub fn set_level(&mut self, name: &str) {
    if let Some(value) = level_value(name) {
      self.threshold = value;
      self.level_name = name.to_string();
    }
  }

  /// Set the name feeding the `successv` suffix.
  pub fn set_name(&mut self, name: impl Into<String>) {
    self.name = name.into();
  }

  /// Set the version feeding the `successv` suffix.
  pub fn set_version(&mut self, version: impl Into<String>) {
    self.version = version.into();
  }

  // -- emitters -----------------------------------------------------------------

  /// `error` → stderr, unconditional.
  pub fn error(&mut self, message: &str) {
    self.write_stderr(Level::Error, message);
  }

  /// `infoerror` → stderr, unconditional.
  pub fn infoerror(&mut self, message: &str) {
    self.write_stderr(Level::Infoerror, message);
  }

  /// `warn` → stdout, level-gated.
  pub fn warn(&mut self, message: &str) {
    self.write_stdout(Level::Warn, message);
  }

  /// `success` → stdout, level-gated.
  pub fn success(&mut self, message: &str) {
    self.write_stdout(Level::Success, message);
  }

  /// `successv` → stdout, level-gated; appends ` · <name>@<version>`.
  pub fn successv(&mut self, message: &str) {
    self.write_stdout(Level::Successv, message);
  }

  /// `info` → stdout, level-gated.
  pub fn info(&mut self, message: &str) {
    self.write_stdout(Level::Info, message);
  }

  /// `help` → stdout, level-gated.
  pub fn help(&mut self, message: &str) {
    self.write_stdout(Level::Help, message);
  }

  /// `verbose` → stdout, level-gated.
  pub fn verbose(&mut self, message: &str) {
    self.write_stdout(Level::Verbose, message);
  }

  /// `debug` → stdout, level-gated.
  pub fn debug(&mut self, message: &str) {
    self.write_stdout(Level::Debug, message);
  }

  fn write_stderr(&mut self, level: Level, message: &str) {
    let formatted = self.format(level, message);
    let _ = writeln!(self.err, "{formatted}");
  }

  fn write_stdout(&mut self, level: Level, message: &str) {
    if level.value() <= self.threshold {
      let formatted = self.format(level, message);
      let _ = writeln!(self.out, "{formatted}");
    }
  }

  /// Format a message with its level prefix and color.
  fn format(&self, level: Level, message: &str) -> String {
    let d = self.depth();
    match level {
      Level::Error => bold(d, &colorize(d, Color::Red, &format!("☠ {message}"))),
      Level::Infoerror => colorize(d, Color::Gray, message),
      Level::Warn => colorize(d, Color::Orangered, &format!("⚠ {message}")),
      Level::Success => colorize(d, Color::Amber, message),
      Level::Successv => colorize(
        d,
        Color::Amber,
        &format!("⟐ {message} · {}@{}", self.name, self.version),
      ),
      Level::Info => colorize(d, Color::Gray, message),
      Level::Help => colorize(d, Color::Dodgerblue, message),
      Level::Verbose | Level::Debug => colorize(d, Color::Plum, &format!("┆ {message}")),
    }
  }

  // -- setLogLevel --------------------------------------------------------------

  /// Apply the log-level options: precedence debug > verbose > quiet(→`error`) >
  /// log_level; no-op when none is set. After a change, logs `setting log level
  /// to: <level>` at debug unless quiet won with `error`.
  pub fn set_log_level(&mut self, options: &LogOptions) {
    let log_level: Option<&str> = if options.debug {
      Some("debug")
    } else if options.verbose {
      Some("verbose")
    } else if options.quiet {
      Some("error")
    } else {
      options.log_level.as_deref()
    };

    let Some(log_level) = log_level else { return };
    self.set_level(log_level);
    if !options.quiet || log_level != "error" {
      self.debug(&format!("setting log level to: {log_level}"));
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use test_support::LoggerCapture;

  fn logger(cap: &LoggerCapture, depth: u16) -> Logger {
    Logger::new(
      Box::new(cap.stdout_writer()),
      Box::new(cap.stderr_writer()),
      depth,
    )
  }

  #[test]
  fn default_level_is_info() {
    let cap = LoggerCapture::new();
    let mut l = logger(&cap, 1);
    assert_eq!(l.level(), "info");
    l.info("hi");
    l.verbose("nope"); // 4 > 2, suppressed
    l.debug("nope"); // 5 > 2, suppressed
    assert_eq!(cap.stdout_lines(), vec!["hi"]);
  }

  #[test]
  fn stream_split_and_prefixes_at_depth_1() {
    let cap = LoggerCapture::new();
    let mut l = logger(&cap, 1);
    l.set_level("debug"); // raise threshold so every stdout level emits
    l.error("boom");
    l.infoerror("side");
    l.warn("careful");
    l.success("done");
    l.info("noted");
    l.help("hint");
    l.verbose("trace");
    l.debug("detail");

    // error + infoerror → stderr; everything else → stdout.
    assert_eq!(cap.stderr_lines(), vec!["☠ boom", "side"]);
    assert_eq!(
      cap.stdout_lines(),
      vec!["⚠ careful", "done", "noted", "hint", "┆ trace", "┆ detail"]
    );
  }

  #[test]
  fn successv_suffix_uses_name_and_version() {
    let cap = LoggerCapture::new();
    let mut l = logger(&cap, 1);
    l.set_name("myapp");
    l.set_version("9.9.9");
    l.successv("saved");
    assert_eq!(cap.stdout_lines(), vec!["⟐ saved · myapp@9.9.9"]);
  }

  #[test]
  // `--quiet` still emits error/infoerror.
  fn quiet_still_emits_error_and_infoerror() {
    let cap = LoggerCapture::new();
    let mut l = logger(&cap, 1);
    l.set_log_level(&LogOptions {
      quiet: true,
      ..Default::default()
    });
    assert_eq!(l.level(), "error");

    l.error("boom");
    l.infoerror("side");
    l.warn("careful"); // 1 > 0, suppressed
    l.info("noted"); // 2 > 0, suppressed
    l.success("done"); // 2 > 0, suppressed

    assert_eq!(cap.stderr_lines(), vec!["☠ boom", "side"]);
    // quiet suppresses everything on stdout, incl. the "setting log level" line.
    assert!(cap.stdout().is_empty());
  }

  #[test]
  // tap: tests/lib/config.test.js:270-297 (setLogLevel precedence)
  fn set_log_level_precedence_debug_wins() {
    let cap = LoggerCapture::new();
    let mut l = logger(&cap, 1);
    l.set_log_level(&LogOptions {
      debug: true,
      verbose: true,
      quiet: true,
      log_level: Some("warn".to_string()),
    });
    assert_eq!(l.level(), "debug");
    // debug threshold => the "setting log level" debug line is emitted.
    assert_eq!(cap.stdout_lines(), vec!["┆ setting log level to: debug"]);
  }

  #[test]
  fn set_log_level_verbose_over_quiet_and_loglevel() {
    let cap = LoggerCapture::new();
    let mut l = logger(&cap, 1);
    l.set_log_level(&LogOptions {
      verbose: true,
      quiet: true,
      log_level: Some("warn".to_string()),
      ..Default::default()
    });
    assert_eq!(l.level(), "verbose");
    // verbose threshold (4) < debug (5), so the debug line does NOT emit.
    assert!(cap.stdout().is_empty());
  }

  #[test]
  fn set_log_level_loglevel_only() {
    let cap = LoggerCapture::new();
    let mut l = logger(&cap, 1);
    l.set_log_level(&LogOptions {
      log_level: Some("warn".to_string()),
      ..Default::default()
    });
    assert_eq!(l.level(), "warn");
  }

  #[test]
  fn set_log_level_none_is_noop() {
    let cap = LoggerCapture::new();
    let mut l = logger(&cap, 1);
    l.set_log_level(&LogOptions::default());
    assert_eq!(l.level(), "info"); // unchanged
    assert!(cap.stdout().is_empty());
  }

  #[test]
  fn set_level_ignores_unknown_name() {
    let cap = LoggerCapture::new();
    let mut l = logger(&cap, 1);
    l.set_level("bogus");
    assert_eq!(l.level(), "info"); // unchanged
                                   // silly is a valid (threshold-only) name.
    l.set_level("silly");
    assert_eq!(l.level(), "silly");
  }

  #[test]
  fn error_is_bold_red_at_depth_24() {
    let cap = LoggerCapture::new();
    let mut l = logger(&cap, 24);
    l.error("boom");
    assert_eq!(
      cap.stderr(),
      "\x1b[1m\x1b[38;2;140;35;50m☠ boom\x1b[39m\x1b[22m\n"
    );
  }

  #[test]
  fn injected_fixed_depth_is_resolved_at_write_time() {
    // `Logger::new` stores a fixed depth (`DepthSource::Fixed`) and resolves it
    // via `depth()` per write, the injection point for tests. It is not derived
    // from the environment at construction.
    let cap = LoggerCapture::new();
    let l = logger(&cap, 8);
    assert_eq!(l.depth(), 8);
  }

  #[test]
  fn stdio_defers_color_depth_resolution() {
    // The real-stdio logger stores `DepthSource::Process` and must not probe the
    // environment at construction; resolution happens on first demand via
    // `depth()`. Constructing it is cheap and does not touch stdout.
    let l = Logger::stdio();
    assert!(matches!(l.depth, DepthSource::Process));
    // Resolving on demand yields the process-wide value (a valid ANSI depth).
    assert!(matches!(l.depth(), 1 | 4 | 8 | 24));
  }
}
