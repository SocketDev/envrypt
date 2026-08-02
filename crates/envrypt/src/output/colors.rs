//! Color functions per depth. Callers pass the depth from [`super::color_depth`].
//!
//! The escape sequences are the contract, byte-identical at depths 1/4/8/24:
//!
//! * depth ≥ 24 AND color in the truecolor map → `\x1b[38;2;R;G;Bm<msg>\x1b[39m`
//!   (only `amber`/`orangered`/`red`; others fall through to 256);
//! * depth ≥ 8 → `\x1b[38;5;<code>m<msg>\x1b[39m`;
//! * depth ≥ 4 → `\x1b[<code>m<msg>\x1b[39m`;
//! * else → the message unchanged.
//!
//! `bold` = `\x1b[1m<msg>\x1b[22m` iff depth ≥ 4.

use crate::errors::EnvryptError;

/// The ten color names the logger styles with. [`get_color`] parses a name string
/// and raises `INVALID_COLOR` for anything outside this set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Amber,
    Blue,
    Gray,
    Green,
    Olive,
    Orangered,
    Plum,
    Red,
    Electricblue,
    Dodgerblue,
}

impl Color {
    /// Parse a color name. `None` → unknown.
    pub fn from_name(name: &str) -> Option<Color> {
        Some(match name {
            "amber" => Color::Amber,
            "blue" => Color::Blue,
            "gray" => Color::Gray,
            "green" => Color::Green,
            "olive" => Color::Olive,
            "orangered" => Color::Orangered,
            "plum" => Color::Plum,
            "red" => Color::Red,
            "electricblue" => Color::Electricblue,
            "dodgerblue" => Color::Dodgerblue,
            _ => return None,
        })
    }

    /// 16-color SGR code.
    fn code16(self) -> u16 {
        match self {
            Color::Amber | Color::Olive | Color::Orangered => 33,
            Color::Blue => 34,
            Color::Green => 32,
            Color::Gray => 37,
            Color::Plum => 35,
            Color::Red => 31,
            Color::Electricblue | Color::Dodgerblue => 36,
        }
    }

    /// 256-color code.
    fn code256(self) -> u16 {
        match self {
            Color::Amber => 136,
            Color::Blue => 21,
            Color::Gray => 244,
            Color::Green => 34,
            Color::Olive => 142,
            Color::Orangered => 130,
            Color::Plum => 182,
            Color::Red => 124,
            Color::Electricblue => 45,
            Color::Dodgerblue => 33,
        }
    }

    /// Truecolor RGB triple, only for the three mapped colors; every other color
    /// returns `None` and falls through to 256.
    fn truecolor(self) -> Option<[u16; 3]> {
        match self {
            Color::Amber => Some([236, 213, 63]),
            Color::Orangered => Some([138, 90, 43]),
            Color::Red => Some([140, 35, 50]),
            _ => None,
        }
    }
}

/// Apply `color` to `message` at `depth`. The enum path used by the logger; never
/// fails.
pub fn colorize(depth: u16, color: Color, message: &str) -> String {
    if depth >= 24 {
        if let Some([r, g, b]) = color.truecolor() {
            return format!("\x1b[38;2;{r};{g};{b}m{message}\x1b[39m");
        }
    }
    if depth >= 8 {
        return format!("\x1b[38;5;{}m{message}\x1b[39m", color.code256());
    }
    if depth >= 4 {
        return format!("\x1b[{}m{message}\x1b[39m", color.code16());
    }
    message.to_string()
}

/// Style `message` by color name, or return an `INVALID_COLOR` error for an unknown
/// color name.
pub fn get_color(depth: u16, color: &str, message: &str) -> Result<String, EnvryptError> {
    match Color::from_name(color) {
        Some(c) => Ok(colorize(depth, c, message)),
        None => Err(EnvryptError::invalid_color(color)),
    }
}

/// Bold `message` (`\x1b[1m…\x1b[22m`) iff depth ≥ 4, else the message unchanged.
pub fn bold(depth: u16, message: &str) -> String {
    if depth >= 4 {
        format!("\x1b[1m{message}\x1b[22m")
    } else {
        message.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // tap: tests/shared/colors.test.js:7-14
    fn get_color_ansi256() {
        assert_eq!(
            get_color(8, "orangered", "hello").unwrap(),
            "\x1b[38;5;130mhello\x1b[39m"
        );
    }

    #[test]
    // tap: tests/shared/colors.test.js:16-23
    fn get_color_truecolor() {
        assert_eq!(
            get_color(24, "amber", "hello").unwrap(),
            "\x1b[38;2;236;213;63mhello\x1b[39m"
        );
    }

    #[test]
    // tap: tests/shared/colors.test.js:25-32
    fn get_color_ansi16() {
        assert_eq!(
            get_color(4, "orangered", "hello").unwrap(),
            "\x1b[33mhello\x1b[39m"
        );
    }

    #[test]
    // tap: tests/shared/colors.test.js:34-41
    fn get_color_no_support() {
        assert_eq!(get_color(1, "orangered", "hello").unwrap(), "hello");
    }

    #[test]
    // tap: tests/shared/colors.test.js:43-54
    fn get_color_invalid_color() {
        let err = get_color(8, "invalid", "hello").unwrap_err();
        assert_eq!(err.message(), "[INVALID_COLOR] Invalid color invalid");
    }

    #[test]
    // tap: tests/shared/colors.test.js:56-63
    fn bold_ansi16() {
        assert_eq!(bold(4, "hello"), "\x1b[1mhello\x1b[22m");
    }

    #[test]
    // tap: tests/shared/colors.test.js:65-72
    fn bold_no_support() {
        assert_eq!(bold(1, "hello"), "hello");
    }

    // ---- full byte-identical matrix at depths 1/4/8/24 --------------------------
    // The expected escape bytes are the frozen contract at each depth.

    #[test]
    fn escape_matrix_matches_reference() {
        // depth 1: everything plain.
        for name in [
            "amber",
            "blue",
            "gray",
            "green",
            "olive",
            "orangered",
            "plum",
            "red",
            "electricblue",
            "dodgerblue",
        ] {
            assert_eq!(get_color(1, name, "hello").unwrap(), "hello");
        }

        // depth 4 (16-color).
        assert_eq!(
            get_color(4, "amber", "hello").unwrap(),
            "\x1b[33mhello\x1b[39m"
        );
        assert_eq!(
            get_color(4, "blue", "hello").unwrap(),
            "\x1b[34mhello\x1b[39m"
        );
        assert_eq!(
            get_color(4, "gray", "hello").unwrap(),
            "\x1b[37mhello\x1b[39m"
        );
        assert_eq!(
            get_color(4, "green", "hello").unwrap(),
            "\x1b[32mhello\x1b[39m"
        );
        assert_eq!(
            get_color(4, "olive", "hello").unwrap(),
            "\x1b[33mhello\x1b[39m"
        );
        assert_eq!(
            get_color(4, "orangered", "hello").unwrap(),
            "\x1b[33mhello\x1b[39m"
        );
        assert_eq!(
            get_color(4, "plum", "hello").unwrap(),
            "\x1b[35mhello\x1b[39m"
        );
        assert_eq!(
            get_color(4, "red", "hello").unwrap(),
            "\x1b[31mhello\x1b[39m"
        );
        assert_eq!(
            get_color(4, "electricblue", "hello").unwrap(),
            "\x1b[36mhello\x1b[39m"
        );
        assert_eq!(
            get_color(4, "dodgerblue", "hello").unwrap(),
            "\x1b[36mhello\x1b[39m"
        );

        // depth 8 (256-color).
        assert_eq!(
            get_color(8, "amber", "hello").unwrap(),
            "\x1b[38;5;136mhello\x1b[39m"
        );
        assert_eq!(
            get_color(8, "blue", "hello").unwrap(),
            "\x1b[38;5;21mhello\x1b[39m"
        );
        assert_eq!(
            get_color(8, "gray", "hello").unwrap(),
            "\x1b[38;5;244mhello\x1b[39m"
        );
        assert_eq!(
            get_color(8, "green", "hello").unwrap(),
            "\x1b[38;5;34mhello\x1b[39m"
        );
        assert_eq!(
            get_color(8, "olive", "hello").unwrap(),
            "\x1b[38;5;142mhello\x1b[39m"
        );
        assert_eq!(
            get_color(8, "orangered", "hello").unwrap(),
            "\x1b[38;5;130mhello\x1b[39m"
        );
        assert_eq!(
            get_color(8, "plum", "hello").unwrap(),
            "\x1b[38;5;182mhello\x1b[39m"
        );
        assert_eq!(
            get_color(8, "red", "hello").unwrap(),
            "\x1b[38;5;124mhello\x1b[39m"
        );
        assert_eq!(
            get_color(8, "electricblue", "hello").unwrap(),
            "\x1b[38;5;45mhello\x1b[39m"
        );
        assert_eq!(
            get_color(8, "dodgerblue", "hello").unwrap(),
            "\x1b[38;5;33mhello\x1b[39m"
        );

        // depth 24 (truecolor only for amber/orangered/red; rest fall through to 256).
        assert_eq!(
            get_color(24, "amber", "hello").unwrap(),
            "\x1b[38;2;236;213;63mhello\x1b[39m"
        );
        assert_eq!(
            get_color(24, "orangered", "hello").unwrap(),
            "\x1b[38;2;138;90;43mhello\x1b[39m"
        );
        assert_eq!(
            get_color(24, "red", "hello").unwrap(),
            "\x1b[38;2;140;35;50mhello\x1b[39m"
        );
        assert_eq!(
            get_color(24, "gray", "hello").unwrap(),
            "\x1b[38;5;244mhello\x1b[39m"
        );
        assert_eq!(
            get_color(24, "dodgerblue", "hello").unwrap(),
            "\x1b[38;5;33mhello\x1b[39m"
        );

        // bold ladder.
        assert_eq!(bold(1, "hello"), "hello");
        assert_eq!(bold(4, "hello"), "\x1b[1mhello\x1b[22m");
        assert_eq!(bold(8, "hello"), "\x1b[1mhello\x1b[22m");
        assert_eq!(bold(24, "hello"), "\x1b[1mhello\x1b[22m");
    }
}
