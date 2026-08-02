//! A faithful port of Node's POSIX `path.join` + `path.normalize` +
//! `normalizeString` (lib/path.js), shared by every call site that must reproduce
//! a JS `path.join(...)` byte for byte:
//!
//!   * `services::precommit`/`services::prebuild` — `path.join(this.directory,
//!     _file)`: a mismatch never matches `git diff HEAD --name-only` output and
//!     diverges in every policy string.
//!   * `resolvers::envs::resolve_directory_filepath` — `path.join(filepath,
//!     filename)`: the result is the row's readable filepath, embedded verbatim in
//!     the `⟐ injected env (N) from <paths>` banner, so `.`/`./`/`sub/.` inputs must
//!     normalize exactly like Node (`path.join('.', '.env')` → `.env`, not
//!     `./.env`).
//!
//! `node_path_join`/`node_path_normalize_posix` are POSIX-only: the
//! run/precommit paths are built with `/` on every platform this crate tests.
//! [`normalize_path`] ports socket-lib's cross-platform normalizer (backslash →
//! forward slash, UNC + Windows namespace preservation), applied at the path
//! boundaries so a Windows `\`-separated path collapses to the `/`-separated
//! form the POSIX helpers expect.

/// Node POSIX `path.join(...parts)`: join non-empty parts with `/`, then
/// `path.normalize`; all-empty → `.`.
pub fn node_path_join(parts: &[&str]) -> String {
    let mut joined: Option<String> = None;
    for &part in parts {
        if part.is_empty() {
            continue;
        }
        match &mut joined {
            None => joined = Some(part.to_string()),
            Some(j) => {
                j.push('/');
                j.push_str(part);
            }
        }
    }
    match joined {
        Some(j) => node_path_normalize_posix(&j),
        None => ".".to_string(),
    }
}

/// Node POSIX `path.normalize(path)` (lib/path.js `posix.normalize`).
pub fn node_path_normalize_posix(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let chars: Vec<char> = path.chars().collect();
    let is_absolute = chars[0] == '/';
    let trailing_separator = *chars.last().unwrap() == '/';
    let mut result = normalize_string_posix(&chars, !is_absolute);
    if result.is_empty() {
        if is_absolute {
            return "/".to_string();
        }
        return if trailing_separator { "./" } else { "." }.to_string();
    }
    if trailing_separator {
        result.push('/');
    }
    if is_absolute {
        format!("/{result}")
    } else {
        result
    }
}

/// Node's `normalizeString(path, allowAboveRoot, '/', isPosixPathSeparator)`
/// (lib/path.js) — resolves `.`/`..` segments and collapses repeated separators.
/// `res` is tracked as `Vec<char>` to mirror Node's UTF-16-code-unit indexing on
/// ASCII paths (the only residual difference is the exotic `res.length` numeric
/// comparison in the `..` branch on non-BMP segment content — unreachable here).
fn normalize_string_posix(chars: &[char], allow_above_root: bool) -> String {
    let len = chars.len() as isize;
    let mut res: Vec<char> = Vec::new();
    let mut last_segment_length: isize = 0;
    let mut last_slash: isize = -1;
    let mut dots: isize = 0;
    let mut code: char = '\0';
    let mut i: isize = 0;
    while i <= len {
        if i < len {
            code = chars[i as usize];
        } else if code == '/' {
            break;
        } else {
            code = '/';
        }

        if code == '/' {
            if last_slash == i - 1 || dots == 1 {
                // NOOP: repeated separator or a lone `.` segment.
            } else if dots == 2 {
                let ends_with_dotdot =
                    res.len() >= 2 && res[res.len() - 1] == '.' && res[res.len() - 2] == '.';
                if res.len() < 2 || last_segment_length != 2 || !ends_with_dotdot {
                    if res.len() > 2 {
                        match res.iter().rposition(|&c| c == '/') {
                            Some(idx) => {
                                res.truncate(idx);
                                last_segment_length = res.len() as isize
                                    - 1
                                    - res
                                        .iter()
                                        .rposition(|&c| c == '/')
                                        .map_or(-1, |p| p as isize);
                            }
                            None => {
                                res.clear();
                                last_segment_length = 0;
                            }
                        }
                        last_slash = i;
                        dots = 0;
                        i += 1;
                        continue;
                    } else if !res.is_empty() {
                        res.clear();
                        last_segment_length = 0;
                        last_slash = i;
                        dots = 0;
                        i += 1;
                        continue;
                    }
                }
                if allow_above_root {
                    if !res.is_empty() {
                        res.push('/');
                    }
                    res.push('.');
                    res.push('.');
                    last_segment_length = 2;
                }
            } else {
                let seg = &chars[(last_slash + 1) as usize..i as usize];
                if !res.is_empty() {
                    res.push('/');
                }
                res.extend_from_slice(seg);
                last_segment_length = i - last_slash - 1;
            }
            last_slash = i;
            dots = 0;
        } else if code == '.' && dots != -1 {
            dots += 1;
        } else {
            dots = -1;
        }
        i += 1;
    }
    res.into_iter().collect()
}

/// True for either path separator (`/` or `\`).
fn is_sep(c: char) -> bool {
    c == '/' || c == '\\'
}

/// Index of the first separator at or after `from`, mirroring
/// `search(path, /[/\\]/, { fromIndex })`.
fn next_slash(chars: &[char], from: usize) -> Option<usize> {
    chars[from..]
        .iter()
        .position(|&c| is_sep(c))
        .map(|i| i + from)
}

/// Whether a `char` segment equals a string.
fn seg_eq(segment: &[char], s: &str) -> bool {
    segment.iter().copied().eq(s.chars())
}

/// Collapses one path segment into `collapsed`, resolving `.`/`..`/empty exactly
/// like the segment loop in socket-lib's `normalizePath`.
fn collapse_segment(
    segment: &[char],
    collapsed: &mut Vec<char>,
    segment_count: &mut isize,
    leading_dot_dots: &mut isize,
    has_prefix: bool,
) {
    if segment.is_empty() || seg_eq(segment, ".") {
        return;
    }
    if seg_eq(segment, "..") {
        if *segment_count > 0 {
            match collapsed.iter().rposition(|&c| c == '/') {
                None => {
                    collapsed.clear();
                    *segment_count = 0;
                    if *leading_dot_dots > 0 && !has_prefix {
                        collapsed.push('.');
                        collapsed.push('.');
                        *leading_dot_dots = 1;
                    }
                }
                Some(last_sep) => {
                    if seg_eq(&collapsed[last_sep + 1..], "..") {
                        collapsed.push('/');
                        collapsed.push('.');
                        collapsed.push('.');
                        *leading_dot_dots += 1;
                    } else {
                        collapsed.truncate(last_sep);
                        *segment_count -= 1;
                    }
                }
            }
        } else if !has_prefix {
            if !collapsed.is_empty() {
                collapsed.push('/');
            }
            collapsed.push('.');
            collapsed.push('.');
            *leading_dot_dots += 1;
        }
    } else {
        if !collapsed.is_empty() {
            collapsed.push('/');
        }
        collapsed.extend_from_slice(segment);
        *segment_count += 1;
    }
}

/// On Windows, convert MSYS drive notation to native: `/c/path` → `C:/path`
/// (and `/c` → `C:/`). A no-op on every other platform.
pub fn msys_drive_to_native(normalized: &str) -> String {
    if cfg!(target_os = "windows") {
        let bytes = normalized.as_bytes();
        if bytes.len() >= 2
            && bytes[0] == b'/'
            && bytes[1].is_ascii_alphabetic()
            && (bytes.len() == 2 || bytes[2] == b'/')
        {
            let letter = bytes[1].to_ascii_uppercase() as char;
            let tail = if bytes.len() == 2 {
                ""
            } else {
                &normalized[3..]
            };
            return format!("{letter}:/{tail}");
        }
    }
    normalized.to_string()
}

// Lock-step from TypeScript: upstream/socket-lib/src/paths/normalize.ts
/// Normalize a path: backslashes → forward slashes, collapse repeated slashes,
/// resolve `.`/`..` segments, preserve UNC (`//server/share`) and Windows
/// namespace (`//./`, `//?/`) prefixes, and return `.` for an empty or fully
/// collapsed path. On Windows, MSYS drive letters `/c/path` become `C:/path`.
pub fn normalize_path(path: &str) -> String {
    let chars: Vec<char> = path.chars().collect();
    let length = chars.len();
    if length == 0 {
        return ".".to_string();
    }
    if length < 2 {
        return if chars[0] == '\\' {
            "/".to_string()
        } else {
            path.to_string()
        };
    }

    let mut start: usize = 0;
    let mut prefix = String::new();

    // Ensure win32 namespaces (`\\?\`, `\\.\`) keep two leading slashes so they
    // survive normalization intact.
    if length > 4 && chars[3] == '\\' {
        let code2 = chars[2];
        if (code2 == '?' || code2 == '.') && chars[0] == '\\' && chars[1] == '\\' {
            start = 2;
            prefix.push_str("//");
        }
    }
    if start == 0 {
        let double_lead = length > 2
            && ((chars[0] == '\\' && chars[1] == '\\' && chars[2] != '\\')
                || (chars[0] == '/' && chars[1] == '/' && chars[2] != '/'));
        if double_lead {
            // A UNC path (`\\server\share`) is valid only with both a server and a
            // share segment; anything else is a run of leading slashes.
            let mut i = 2;
            while i < length && is_sep(chars[i]) {
                i += 1;
            }
            let mut first_segment_end: Option<usize> = None;
            while i < length {
                if is_sep(chars[i]) {
                    first_segment_end = Some(i);
                    break;
                }
                i += 1;
            }
            let mut has_second_segment = false;
            if let Some(end) = first_segment_end {
                if end > 2 {
                    i = end;
                    while i < length && is_sep(chars[i]) {
                        i += 1;
                    }
                    if i < length {
                        has_second_segment = true;
                    }
                }
            }
            if first_segment_end.is_some_and(|end| end > 2) && has_second_segment {
                start = 2;
                prefix.push_str("//");
            } else {
                while start < length && is_sep(chars[start]) {
                    start += 1;
                }
                if start != 0 {
                    prefix.push('/');
                }
            }
        } else {
            // Trim leading slashes for regular paths.
            while start < length && is_sep(chars[start]) {
                start += 1;
            }
            if start != 0 {
                prefix.push('/');
            }
        }
    }

    let has_prefix = !prefix.is_empty();

    let mut next_index = next_slash(&chars, start);
    if next_index.is_none() {
        let segment: String = chars[start..].iter().collect();
        if segment == "." || segment.is_empty() {
            return if has_prefix { prefix } else { ".".to_string() };
        }
        if segment == ".." {
            if has_prefix {
                let trimmed = &prefix[..prefix.len() - 1];
                return if trimmed.is_empty() {
                    "/".to_string()
                } else {
                    trimmed.to_string()
                };
            }
            return "..".to_string();
        }
        return msys_drive_to_native(&format!("{prefix}{segment}"));
    }

    let mut collapsed: Vec<char> = Vec::new();
    let mut segment_count: isize = 0;
    let mut leading_dot_dots: isize = 0;
    while let Some(idx) = next_index {
        collapse_segment(
            &chars[start..idx],
            &mut collapsed,
            &mut segment_count,
            &mut leading_dot_dots,
            has_prefix,
        );
        start = idx + 1;
        while start < length && is_sep(chars[start]) {
            start += 1;
        }
        next_index = next_slash(&chars, start);
    }
    collapse_segment(
        &chars[start..],
        &mut collapsed,
        &mut segment_count,
        &mut leading_dot_dots,
        has_prefix,
    );

    if collapsed.is_empty() {
        return if has_prefix { prefix } else { ".".to_string() };
    }
    let collapsed_str: String = collapsed.iter().collect();
    // A bare drive letter from a drive ROOT keeps its slash: `D:\` and `D:/`
    // normalize to `D:/`, detected by a separator immediately after the colon in
    // the original input (index 2).
    if collapsed.len() == 2
        && collapsed[0].is_ascii_alphabetic()
        && collapsed[1] == ':'
        && length > 2
        && is_sep(chars[2])
    {
        return msys_drive_to_native(&format!("{prefix}{collapsed_str}/"));
    }
    msys_drive_to_native(&format!("{prefix}{collapsed_str}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Values captured from Node's `require('path').join(a, b)`.
    #[test]
    fn join_matches_node_path_join() {
        let cases: &[(&str, &str, &str)] = &[
            ("./sub", ".env", "sub/.env"),
            ("sub", ".env", "sub/.env"),
            (".", ".env", ".env"),
            ("./", ".env", ".env"),
            ("", ".env", ".env"),
            ("sub/", ".env", "sub/.env"),
            ("sub//", ".env", "sub/.env"),
            ("sub/./", ".env", "sub/.env"),
            (".//", ".env", ".env"),
            ("./sub/", ".env", "sub/.env"),
            ("a/b", ".env", "a/b/.env"),
            ("./a/b", ".env", "a/b/.env"),
            ("sub", "packages/app/.env", "sub/packages/app/.env"),
            ("../foo", ".env", "../foo/.env"),
            ("../foo", "packages/app/.env", "../foo/packages/app/.env"),
            ("sub/..", ".env", ".env"),
            ("a/../b", ".env", "b/.env"),
            ("../..", ".env", "../../.env"),
            ("./sub/../other", ".env", "other/.env"),
            ("sub/.", ".env", "sub/.env"),
            ("..", ".env", "../.env"),
            ("a/b/../..", ".env", ".env"),
            ("/abs", ".env", "/abs/.env"),
            ("/abs/.", ".env", "/abs/.env"),
            ("/", ".env", "/.env"),
        ];
        for (a, b, expected) in cases {
            assert_eq!(
                node_path_join(&[a, b]),
                *expected,
                "path.join({a:?}, {b:?})"
            );
        }
    }

    #[test]
    fn join_edge_shapes() {
        assert_eq!(node_path_join(&[]), ".");
        assert_eq!(node_path_join(&["", ""]), ".");
        assert_eq!(node_path_join(&["."]), ".");
        assert_eq!(node_path_join(&["a/", ""]), "a/");
        assert_eq!(node_path_normalize_posix(""), ".");
        assert_eq!(node_path_normalize_posix("./"), "./");
        assert_eq!(node_path_normalize_posix("/../.."), "/");
    }

    // The doc examples from socket-lib's `normalizePath` JSDoc.
    #[test]
    fn normalize_path_matches_socket_lib_examples() {
        assert_eq!(normalize_path("foo/bar//baz"), "foo/bar/baz");
        assert_eq!(normalize_path("foo/./bar"), "foo/bar");
        assert_eq!(normalize_path("foo/bar/../baz"), "foo/baz");
        assert_eq!(
            normalize_path("C:\\code\\app\\file.txt"),
            "C:/code/app/file.txt"
        );
        assert_eq!(normalize_path(""), ".");
    }

    #[test]
    fn normalize_path_converts_backslashes_to_forward_slashes() {
        assert_eq!(normalize_path("foo\\bar\\baz"), "foo/bar/baz");
        assert_eq!(normalize_path("sub\\.env"), "sub/.env");
    }
}
