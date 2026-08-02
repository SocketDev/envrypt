//! Color-depth detection: a full port of Node's
//! `tty.WriteStream.prototype.getColorDepth`.
//!
//! `getColorDepth` never inspects `this.fd` or the stream's TTY-ness. It is a pure
//! function of the environment (plus the platform on Windows), so it returns the
//! same depth whether stdout is a TTY or a pipe. Redirected and piped output still
//! gets full ANSI whenever the env indicates color. Keep detection env-only; a TTY
//! gate would break that.
//!
//! [`detect_depth`] reproduces Node v26.5.0's algorithm (`lib/internal/tty.js`),
//! confirmed branch by branch against Node v26.5.0 by both
//! `WriteStream.prototype.getColorDepth(env)` and the ANSI observed on `run -- true`.
//! The resolution order is (a monochrome result is depth `1`):
//!
//! 1. `FORCE_COLOR` present → exact-string switch (`''`/`1`/`true`→4, `2`→8, `3`→24,
//!    anything else incl. `0`/`false`→1);
//! 2. else `NODE_DISABLE_COLORS`/`NO_COLOR` present **and non-empty**, or `TERM=dumb` → 1
//!    (Node uses `!== undefined && !== ''`, so an *empty* `NO_COLOR` does NOT disable);
//! 3. else **Windows only**: `os.release()` ladder ([`windows_release_depth`]) — this
//!    branch REPLACES every env branch below (TMUX/CI/TERM_PROGRAM/COLORTERM/TERM are
//!    unreachable on win32);
//! 4. else `TMUX` truthy → 24;
//! 5. else Azure DevOps (`TF_BUILD` and `AGENT_NAME` both present) → 4;
//! 6. else `CI` present → first matching vendor in [`CI_ENVS_MAP`] (insertion order),
//!    else `CI_NAME=codeship` → 8, else → 1;
//! 7. else `TEAMCITY_VERSION` present → version regex ([`teamcity_supports_color`]) → 4/1;
//! 8. else `TERM_PROGRAM` switch (`iTerm.app`→8 or 24 by version, `HyperTerm`/`MacTerm`→24,
//!    `Apple_Terminal`→8);
//! 9. else `COLORTERM` exactly `truecolor`/`24bit` → 24;
//! 10. else non-empty `TERM`: contains `truecolor`→24; `xterm-256*`→8; the [`term_envs_lookup`]
//!     table; the [`term_regex_matches`] list → 4 (both on the lowercased `TERM`);
//! 11. else any non-empty `COLORTERM` → 4;
//! 12. else → 1.
//!
//! Depth is injected as a function parameter into `colors`/`logger`; this module
//! produces the process-wide value, computed lazily on first access via
//! [`process_color_depth`].

use std::sync::LazyLock;

/// The `TERM`-only fallback for the deno scenario, where `getColorDepth` throws:
/// `256color`/`xterm` → 8, else 4. This is the deno heuristic, distinct from the
/// normal-Node resolution in [`detect_depth`]; the test suite pins it exact.
pub fn fallback_depth(term: Option<&str>) -> u16 {
    match term {
        Some(t) if t.contains("256color") || t.contains("xterm") => 8,
        _ => 4,
    }
}

/// The color-relevant environment variables, snapshotted from the real process
/// environment by [`DepthEnv::from_process`]. Nothing outside this set influences
/// `getColorDepth`, so snapshotting only these keeps presence/value lookups correct
/// and cheap.
const RELEVANT_VARS: &[&str] = &[
    "FORCE_COLOR",
    "NO_COLOR",
    "NODE_DISABLE_COLORS",
    "TERM",
    "TMUX",
    "TF_BUILD",
    "AGENT_NAME",
    "CI",
    "CI_NAME",
    "APPVEYOR",
    "BUILDKITE",
    "CIRCLECI",
    "DRONE",
    "GITEA_ACTIONS",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "TRAVIS",
    "TEAMCITY_VERSION",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "COLORTERM",
];

/// A minimal environment view for color-depth detection: maps a variable name to its
/// value, or absent. This mirrors Node's `process.env`, where `key in env` (presence)
/// and a truthy value are distinct — both distinctions matter to `getColorDepth`
/// (e.g. `NO_COLOR=''` is present-but-falsy → does NOT disable color; `CI=''` is
/// present → still enters the CI branch). Injected as a function parameter so
/// [`detect_depth`] stays a pure function testable without touching global env.
#[derive(Debug, Clone, Default)]
pub struct DepthEnv {
    vars: std::collections::HashMap<String, String>,
}

impl DepthEnv {
    /// Build from explicit `(name, value)` pairs (unit tests / injection). A pair with
    /// an empty value models a variable that is **present but empty** — Node
    /// distinguishes `key in env` from a truthy value.
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        DepthEnv {
            vars: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    /// Snapshot the color-relevant variables ([`RELEVANT_VARS`]) from the real process
    /// environment. Presence is captured via `var_os` (so a present-but-non-UTF-8
    /// value still counts as present); the value is read lossily (color detection only
    /// ever compares ASCII tokens).
    fn from_process() -> Self {
        let mut vars = std::collections::HashMap::new();
        for &key in RELEVANT_VARS {
            if let Some(val) = std::env::var_os(key) {
                vars.insert(key.to_string(), val.to_string_lossy().into_owned());
            }
        }
        DepthEnv { vars }
    }

    /// The variable's value, or `None` when absent (Node `env[key] === undefined` /
    /// `!(key in env)`).
    fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(String::as_str)
    }

    /// Node truthiness: present **and** non-empty (`env[key]` is a truthy string).
    fn truthy(&self, key: &str) -> bool {
        self.get(key).is_some_and(|v| !v.is_empty())
    }
}

/// Node's `CI_ENVS_MAP` (`lib/internal/tty.js`), in insertion order — the first vendor
/// key present in the env (when `CI` is also present) fixes the depth. Values probed
/// against Node v26.5.0: `CIRCLECI`/`GITEA_ACTIONS`/`GITHUB_ACTIONS` → 24 (`COLORS_16m`),
/// the rest → 8 (`COLORS_256`).
#[cfg(not(windows))]
const CI_ENVS_MAP: &[(&str, u16)] = &[
    ("APPVEYOR", 8),
    ("BUILDKITE", 8),
    ("CIRCLECI", 24),
    ("DRONE", 8),
    ("GITEA_ACTIONS", 24),
    ("GITHUB_ACTIONS", 24),
    ("GITLAB_CI", 8),
    ("TRAVIS", 8),
];

/// Observable Node `getColorDepth()` behavior, a pure function of the environment
/// (never TTY-gated). See the module docs for the full ordered ladder.
pub fn detect_depth(env: &DepthEnv) -> u16 {
    // 1. FORCE_COLOR present overrides everything (Node: `env.FORCE_COLOR !== undefined`).
    //    Probed (Node v26.5): ''/1/true→4, 2→8, 3→24, 0/false/none/16/-1/junk→1.
    if let Some(force) = env.get("FORCE_COLOR") {
        return match force {
            "" | "1" | "true" => 4,
            "2" => 8,
            "3" => 24,
            _ => 1,
        };
    }
    // 2. NODE_DISABLE_COLORS / NO_COLOR present AND non-empty, or TERM=dumb → monochrome.
    //    Node uses `!== undefined && !== ''`; probed: NO_COLOR='' does NOT disable.
    if env.truthy("NODE_DISABLE_COLORS")
        || env.truthy("NO_COLOR")
        || env.get("TERM") == Some("dumb")
    {
        return 1;
    }
    // 3. win32: the os.release() ladder REPLACES all env-based detection below (Node
    //    returns from the win32 branch before reaching TMUX/CI/TERM_PROGRAM/…). Cannot
    //    be probed on the mac/Linux host — verified in CI (deferredToCI).
    #[cfg(windows)]
    {
        let version = windows_version::OsVersion::current();
        windows_release_depth(version.major, version.build)
    }
    #[cfg(not(windows))]
    {
        detect_depth_env(env)
    }
}

/// Steps 4-12 of Node's `getColorDepth` — the env-only branches that run on every
/// non-win32 platform (`lib/internal/tty.js`).
#[cfg(not(windows))]
fn detect_depth_env(env: &DepthEnv) -> u16 {
    // 4. TMUX truthy → truecolor. Probed: TMUX=1/0 → 24, TMUX='' (falsy) → falls through.
    if env.truthy("TMUX") {
        return 24;
    }
    // 5. Azure DevOps: TF_BUILD and AGENT_NAME both present (hasOwn, any value) → 16-color.
    //    Probed: {TF_BUILD,AGENT_NAME} → 4; TF_BUILD alone → falls through.
    if env.get("TF_BUILD").is_some() && env.get("AGENT_NAME").is_some() {
        return 4;
    }
    // 6. CI present (hasOwn, any value incl. empty): first CI_ENVS_MAP vendor present wins;
    //    else CI_NAME=codeship → 8; else → 1. Probed: CI+GITHUB_ACTIONS→24, CI+TRAVIS→8,
    //    CI alone / CI=foo → 1.
    if env.get("CI").is_some() {
        for &(name, depth) in CI_ENVS_MAP {
            if env.get(name).is_some() {
                return depth;
            }
        }
        if env.get("CI_NAME") == Some("codeship") {
            return 8;
        }
        return 1;
    }
    // 7. TEAMCITY_VERSION present → version regex → 16-color, else monochrome. Probed:
    //    9.1.5→4, 2019.1→4, 8.0.0→1, 9.0.0→1, ''→1.
    if let Some(version) = env.get("TEAMCITY_VERSION") {
        return if teamcity_supports_color(version) {
            4
        } else {
            1
        };
    }
    // 8. TERM_PROGRAM switch. Probed: iTerm.app (no ver / ^[0-2]\.)→8, iTerm.app 3.x→24,
    //    HyperTerm/MacTerm→24, Apple_Terminal→8, unknown→falls through.
    match env.get("TERM_PROGRAM") {
        Some("iTerm.app") => {
            // Node: `!env.TERM_PROGRAM_VERSION || /^[0-2]\./.test(version)` → 256, else 16m.
            let legacy = match env.get("TERM_PROGRAM_VERSION") {
                None | Some("") => true,
                Some(version) => iterm_version_legacy(version),
            };
            return if legacy { 8 } else { 24 };
        }
        Some("HyperTerm") | Some("MacTerm") => return 24,
        Some("Apple_Terminal") => return 8,
        _ => {}
    }
    // 9. COLORTERM exactly truecolor/24bit → 24 (case-sensitive `===`).
    if matches!(env.get("COLORTERM"), Some("truecolor") | Some("24bit")) {
        return 24;
    }
    // 10. Non-empty TERM (`if (env.TERM)`): `/truecolor/` and `/^xterm-256/` test the RAW
    //     value (case-sensitive); the TERM_ENVS table and regexp list use the lowercased
    //     value. Probed: xterm-256color→8, XTERM-256COLOR→4, xterm-kitty→24, foo-truecolor
    //     →24, screen-256color→4, vt220→4, xterm-direct→4.
    if let Some(term) = env.get("TERM").filter(|t| !t.is_empty()) {
        if term.contains("truecolor") {
            return 24;
        }
        if term.starts_with("xterm-256") {
            return 8;
        }
        let term_lower = term.to_lowercase();
        if let Some(depth) = term_envs_lookup(&term_lower) {
            return depth;
        }
        if term_regex_matches(&term_lower) {
            return 4;
        }
    }
    // 11. Any (non-empty) COLORTERM → basic color. Probed: COLORTERM=yes → 4.
    if env.truthy("COLORTERM") {
        return 4;
    }
    // 12. No color signal → monochrome (the scrubbed standard_env/conformance default).
    1
}

/// Node's win32 `os.release()` branch (`lib/internal/tty.js`): `os.release()` is split on
/// `.` into `[major, minor, build]`; when `major >= 10`, `build >= 14931` → 24 (first
/// Win10 build with TrueColor) and `build >= 10586` → 8 (first Win10 build with 256
/// colors); otherwise → 4. Pure so it is unit-testable on any host; `major`/`build` come
/// from `windows_version::OsVersion` on Windows only (see [`detect_depth`]).
#[cfg(any(windows, test))]
fn windows_release_depth(major: u32, build: u32) -> u16 {
    if major >= 10 {
        if build >= 14931 {
            return 24;
        }
        if build >= 10586 {
            return 8;
        }
    }
    4
}

/// Node `TERM_ENVS` exact-match table (`lib/internal/tty.js`), keyed on the **lowercased**
/// `TERM`. `mosh`/`rxvt-unicode-24bit`/`terminator`/`xterm-kitty` are truecolor (24); the
/// rest are 16-color (4). Returns `None` for anything else so the caller falls through to
/// the regex list.
#[cfg(not(windows))]
fn term_envs_lookup(term_lower: &str) -> Option<u16> {
    Some(match term_lower {
        "mosh" | "rxvt-unicode-24bit" | "terminator" | "xterm-kitty" => 24,
        "eterm" | "cons25" | "console" | "cygwin" | "dtterm" | "gnome" | "hurd" | "jfbterm"
        | "konsole" | "kterm" | "mlterm" | "putty" | "st" => 4,
        _ => return None,
    })
}

/// Node's `^con[0-9]*x[0-9]` `TERM` pattern (e.g. `con80x25`).
#[cfg(not(windows))]
fn matches_con_pattern(term: &str) -> bool {
    let Some(rest) = term.strip_prefix("con") else {
        return false;
    };
    let after_digits = rest.trim_start_matches(|c: char| c.is_ascii_digit());
    let Some(after_x) = after_digits.strip_prefix('x') else {
        return false;
    };
    after_x.starts_with(|c: char| c.is_ascii_digit())
}

/// Node's `TERM_ENVS_REG_EXP` list (`lib/internal/tty.js`), run on the lowercased `TERM`:
/// substring patterns (`ansi`/`color`/`linux`/`direct`) plus anchored ones
/// (`^rxvt`/`^screen`/`^xterm`/`^vt100`/`^vt220`) and the `con…x…` pattern → 16-color.
#[cfg(not(windows))]
fn term_regex_matches(term_lower: &str) -> bool {
    term_lower.contains("ansi")
        || term_lower.contains("color")
        || term_lower.contains("linux")
        || term_lower.contains("direct")
        || matches_con_pattern(term_lower)
        || term_lower.starts_with("rxvt")
        || term_lower.starts_with("screen")
        || term_lower.starts_with("xterm")
        || term_lower.starts_with("vt100")
        || term_lower.starts_with("vt220")
}

/// `/^[0-2]\./` on a non-empty `TERM_PROGRAM_VERSION` — Node treats iTerm.app versions
/// `0.x`/`1.x`/`2.x` as legacy (256-color); `3.x+` gets truecolor.
#[cfg(not(windows))]
fn iterm_version_legacy(version: &str) -> bool {
    let b = version.as_bytes();
    b.len() >= 2 && matches!(b[0], b'0'..=b'2') && b[1] == b'.'
}

/// Node's TeamCity color test: `/^(9\.(0*[1-9]\d*)\.|\d{2,}\.)/` on `TEAMCITY_VERSION`.
/// Alternative A matches a `9.<nonzero>.` prefix (leading zeros in the minor allowed,
/// but the minor must have a non-zero digit); alternative B matches a `<2+ digits>.`
/// prefix. Both are anchored at the start.
#[cfg(not(windows))]
fn teamcity_supports_color(version: &str) -> bool {
    let b = version.as_bytes();

    // Alternative A: ^9\.(0*[1-9]\d*)\.
    let alt_a = || {
        if b.len() < 2 || b[0] != b'9' || b[1] != b'.' {
            return false;
        }
        let mut i = 2;
        // 0*
        while i < b.len() && b[i] == b'0' {
            i += 1;
        }
        // [1-9]  (0* already consumed leading zeros, so this requires a non-zero digit)
        if i >= b.len() || !(b'1'..=b'9').contains(&b[i]) {
            return false;
        }
        i += 1;
        // \d*
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        // \.
        i < b.len() && b[i] == b'.'
    };

    // Alternative B: ^\d{2,}\.  (two or more leading digits immediately followed by `.`)
    let alt_b = || {
        let mut i = 0;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        i >= 2 && i < b.len() && b[i] == b'.'
    };

    alt_a() || alt_b()
}

/// The process-wide color depth, computed once on first access and cached for the
/// process lifetime (`LazyLock`). Node recomputes per message, but the inputs (env
/// only, plus the OS release on Windows) do not change mid-process, so caching is
/// behavior-invariant.
pub fn process_color_depth() -> u16 {
    static DEPTH: LazyLock<u16> = LazyLock::new(|| detect_depth(&DepthEnv::from_process()));
    *DEPTH
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- fallback_depth: deno "catch" branch ------------------------------------
    // These exercise the throw fallback, which is exactly `fallback_depth`. The
    // depth-from-a-live-`WriteStream.prototype` case has no Rust equivalent.

    #[test]
    // tap: tests/lib/helpers/colorDepth.test.js:20-29
    fn fallback_term_256color_is_8() {
        assert_eq!(fallback_depth(Some("xterm-256color")), 8);
    }

    #[test]
    // tap: tests/lib/helpers/colorDepth.test.js:31-38
    fn fallback_no_term_is_4() {
        assert_eq!(fallback_depth(None), 4);
    }

    #[test]
    // tap: tests/lib/helpers/colorDepth.test.js:40-49
    fn fallback_other_term_is_4() {
        assert_eq!(fallback_depth(Some("something else")), 4);
    }

    #[test]
    fn fallback_bare_xterm_is_8() {
        assert_eq!(fallback_depth(Some("xterm")), 8);
    }

    // ---- windows_release_depth: pure os.release() ladder (unit-testable everywhere) --
    // Node lib/internal/tty.js win32 build thresholds. This branch is otherwise
    // unprobeable on the mac/Linux host (deferredToCI).

    #[test]
    fn windows_release_ladder() {
        // major < 10 → 16-color regardless of build.
        assert_eq!(windows_release_depth(6, 99999), 4); // Windows 7/8.x
                                                        // major >= 10, below the 256-color build → 16-color.
        assert_eq!(windows_release_depth(10, 10585), 4);
        // 256-color range: [10586, 14931).
        assert_eq!(windows_release_depth(10, 10586), 8);
        assert_eq!(windows_release_depth(10, 14930), 8);
        // TrueColor: build >= 14931 (modern Windows 10/11).
        assert_eq!(windows_release_depth(10, 14931), 24);
        assert_eq!(windows_release_depth(10, 19045), 24);
        assert_eq!(windows_release_depth(10, 22631), 24);
    }

    // ---- detect_depth: full Node v26.5 matrix (non-win32) -------------------------
    // Every expectation below was probed against Node v26.5.0 via
    // `tty.WriteStream.prototype.getColorDepth(env)` and cross-checked against the
    // ANSI emitted by `run -- true`. On win32 detect_depth takes the os.release()
    // branch instead, so these are gated to non-Windows.

    #[cfg(not(windows))]
    fn depth(pairs: &[(&str, &str)]) -> u16 {
        detect_depth(&DepthEnv::from_pairs(pairs))
    }

    #[test]
    #[cfg(not(windows))]
    fn no_signal_is_depth_1() {
        // Scrubbed default → monochrome (matches the observed end-to-end behavior).
        assert_eq!(depth(&[]), 1);
        // Present-but-empty TERM/COLORTERM are falsy in Node → still no signal.
        assert_eq!(depth(&[("TERM", ""), ("COLORTERM", "")]), 1);
        // Unrecognized TERM → Node's final fall-through (NOT 4).
        assert_eq!(depth(&[("TERM", "foo")]), 1);
    }

    #[test]
    #[cfg(not(windows))]
    fn force_color_ladder() {
        // FORCE_COLOR overrides even strong color signals. Probed values.
        for (value, want) in [
            ("", 4),
            ("1", 4),
            ("true", 4),
            ("2", 8),
            ("3", 24),
            ("0", 1),
            ("false", 1),
            ("none", 1),
            ("16", 1),
            ("-1", 1),
            ("xyz", 1),
        ] {
            assert_eq!(
                depth(&[
                    ("FORCE_COLOR", value),
                    ("TERM", "xterm-256color"),
                    ("COLORTERM", "truecolor"),
                ]),
                want,
                "FORCE_COLOR={value:?}"
            );
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn no_color_and_node_disable_colors() {
        // Present AND non-empty → monochrome, overriding a 256-color TERM.
        assert_eq!(depth(&[("NO_COLOR", "1"), ("TERM", "xterm-256color")]), 1);
        assert_eq!(
            depth(&[("NODE_DISABLE_COLORS", "1"), ("TERM", "xterm-256color")]),
            1
        );
        // Present-but-EMPTY does NOT disable (Node `!== '' `): TERM wins → 8. Probed.
        assert_eq!(depth(&[("NO_COLOR", ""), ("TERM", "xterm-256color")]), 8);
        assert_eq!(
            depth(&[("NODE_DISABLE_COLORS", ""), ("TERM", "xterm-256color")]),
            8
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn term_dumb_is_depth_1_even_with_colorterm() {
        assert_eq!(depth(&[("TERM", "dumb"), ("COLORTERM", "truecolor")]), 1);
    }

    #[test]
    #[cfg(not(windows))]
    fn tmux_branch() {
        // TMUX truthy → 24, and it beats a screen TERM and even a CI vendor. Probed.
        assert_eq!(depth(&[("TMUX", "1")]), 24);
        assert_eq!(depth(&[("TMUX", "1"), ("TERM", "screen-256color")]), 24);
        assert_eq!(
            depth(&[("TMUX", "1"), ("CI", "1"), ("GITHUB_ACTIONS", "1")]),
            24
        );
        // Empty TMUX is falsy → falls through (no other signal → 1). Probed.
        assert_eq!(depth(&[("TMUX", "")]), 1);
    }

    #[test]
    #[cfg(not(windows))]
    fn azure_devops_branch() {
        // Both keys present (even empty values) → 4. Probed.
        assert_eq!(depth(&[("TF_BUILD", "1"), ("AGENT_NAME", "x")]), 4);
        assert_eq!(depth(&[("TF_BUILD", ""), ("AGENT_NAME", "")]), 4);
        // TF_BUILD alone → falls through → 1. Probed.
        assert_eq!(depth(&[("TF_BUILD", "1")]), 1);
    }

    #[test]
    #[cfg(not(windows))]
    fn ci_branch_matrix() {
        // CI present + vendor. Probed against Node v26.5.
        assert_eq!(depth(&[("CI", "true"), ("GITHUB_ACTIONS", "true")]), 24);
        assert_eq!(depth(&[("CI", "true"), ("GITEA_ACTIONS", "1")]), 24);
        assert_eq!(depth(&[("CI", "true"), ("CIRCLECI", "1")]), 24);
        assert_eq!(depth(&[("CI", "true"), ("TRAVIS", "1")]), 8);
        assert_eq!(depth(&[("CI", "true"), ("APPVEYOR", "1")]), 8);
        assert_eq!(depth(&[("CI", "true"), ("BUILDKITE", "1")]), 8);
        assert_eq!(depth(&[("CI", "true"), ("DRONE", "1")]), 8);
        assert_eq!(depth(&[("CI", "true"), ("GITLAB_CI", "1")]), 8);
        assert_eq!(depth(&[("CI", "1"), ("CI_NAME", "codeship")]), 8);
        // CI present, no known vendor → 1 (incl. empty/arbitrary CI value). Probed.
        assert_eq!(depth(&[("CI", "true")]), 1);
        assert_eq!(depth(&[("CI", "")]), 1);
        assert_eq!(depth(&[("CI", "foo")]), 1);
        // The CI branch is gated on CI presence: GITHUB_ACTIONS alone (no CI) → 1. Probed.
        assert_eq!(depth(&[("GITHUB_ACTIONS", "true")]), 1);
    }

    #[test]
    #[cfg(not(windows))]
    fn teamcity_branch() {
        // Version regex /^(9\.(0*[1-9]\d*)\.|\d{2,}\.)/. Probed.
        assert_eq!(depth(&[("TEAMCITY_VERSION", "9.1.5")]), 4);
        assert_eq!(depth(&[("TEAMCITY_VERSION", "2019.1")]), 4);
        assert_eq!(depth(&[("TEAMCITY_VERSION", "9.01.0")]), 4); // 0*[1-9] allows leading zero
        assert_eq!(depth(&[("TEAMCITY_VERSION", "10.0")]), 4); // \d{2,}\.
        assert_eq!(depth(&[("TEAMCITY_VERSION", "8.0.0")]), 1); // single leading digit, not 9
        assert_eq!(depth(&[("TEAMCITY_VERSION", "9.0.0")]), 1); // 9.0. has no non-zero minor
        assert_eq!(depth(&[("TEAMCITY_VERSION", "")]), 1);
    }

    #[test]
    #[cfg(not(windows))]
    fn term_program_branch() {
        // Probed against Node v26.5.
        assert_eq!(depth(&[("TERM_PROGRAM", "iTerm.app")]), 8);
        assert_eq!(
            depth(&[
                ("TERM_PROGRAM", "iTerm.app"),
                ("TERM_PROGRAM_VERSION", "2.9")
            ]),
            8
        );
        assert_eq!(
            depth(&[
                ("TERM_PROGRAM", "iTerm.app"),
                ("TERM_PROGRAM_VERSION", "3.4")
            ]),
            24
        );
        assert_eq!(depth(&[("TERM_PROGRAM", "Apple_Terminal")]), 8);
        assert_eq!(depth(&[("TERM_PROGRAM", "HyperTerm")]), 24);
        assert_eq!(depth(&[("TERM_PROGRAM", "MacTerm")]), 24);
        // TERM_PROGRAM is checked BEFORE COLORTERM: Apple_Terminal beats COLORTERM=truecolor.
        assert_eq!(
            depth(&[
                ("TERM_PROGRAM", "Apple_Terminal"),
                ("COLORTERM", "truecolor")
            ]),
            8
        );
        // Unknown TERM_PROGRAM → falls through. Probed: vscode alone → 1.
        assert_eq!(depth(&[("TERM_PROGRAM", "vscode")]), 1);
    }

    #[test]
    #[cfg(not(windows))]
    fn colorterm_truecolor_is_24_and_case_sensitive() {
        assert_eq!(depth(&[("COLORTERM", "truecolor")]), 24);
        assert_eq!(depth(&[("COLORTERM", "24bit")]), 24);
        // truecolor beats TERM.
        assert_eq!(
            depth(&[("TERM", "xterm-256color"), ("COLORTERM", "truecolor")]),
            24
        );
        // Case-sensitive: "TrueColor" is not the truecolor token → falls to plain
        // COLORTERM → 4 (Node's strict `===`).
        assert_eq!(depth(&[("COLORTERM", "TrueColor")]), 4);
    }

    #[test]
    #[cfg(not(windows))]
    fn term_resolution_matches_node() {
        // Probed against Node v26.5 (raw `/^xterm-256/` + `/truecolor/`, lowercased
        // TERM_ENVS table + regexp).
        for (term, want) in [
            ("xterm-256color", 8),
            ("xterm-256", 8),
            ("XTERM-256COLOR", 4), // raw ^xterm-256 is case-sensitive → lowercased ^xterm
            ("xterm-16color", 4),
            ("xterm", 4),
            ("screen-256color", 4),
            ("screen", 4),
            ("vt100", 4),
            ("vt220", 4),
            ("rxvt", 4),
            ("rxvt-unicode-256color", 4),
            ("con80x25", 4),
            ("ansi", 4),
            ("linux", 4),
            ("xterm-direct", 4),
            ("abc-color", 4),
            ("foo-truecolor", 24), // /truecolor/ substring on raw TERM
            // TERM_ENVS truecolor entries.
            ("mosh", 24),
            ("rxvt-unicode-24bit", 24),
            ("terminator", 24),
            ("xterm-kitty", 24),
            // TERM_ENVS 16-color entries.
            ("gnome", 4),
            ("konsole", 4),
            ("console", 4),
            // Unrecognized → no color.
            ("foo", 1),
            ("conemu", 1),
        ] {
            assert_eq!(depth(&[("TERM", term)]), want, "TERM={term}");
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn plain_colorterm_is_4() {
        // COLORTERM present but not truecolor, no usable TERM → basic color. Probed.
        assert_eq!(depth(&[("COLORTERM", "yes")]), 4);
        // COLORTERM=1 with a 256-color TERM → TERM wins → 8.
        assert_eq!(depth(&[("TERM", "xterm-256color"), ("COLORTERM", "1")]), 8);
    }

    #[test]
    #[cfg(not(windows))]
    fn env_driven_ignores_tty_ness() {
        // Detection is purely env-driven, so these hold identically on a pipe or a
        // TTY.
        assert_eq!(depth(&[("TERM", "xterm-256color")]), 8);
        assert_eq!(depth(&[("COLORTERM", "truecolor")]), 24);
    }
}
