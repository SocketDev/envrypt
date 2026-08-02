//! Formats a public key's first 6 hex characters as `XXX XXX`.
//!
//! Uppercases the first 6 characters and splits them into two groups (e.g.
//! `027c9c…` → `027 C9C`). Shown in keychain status lines and the
//! `[ACCESS_APPROVAL_REQUIRED] … approve (027 C9C)` provider message. An empty
//! input yields `""`.

/// Uppercases a public key's first 6 characters and groups them `XXX XXX`. Keys
/// are ASCII hex, so character slicing needs no special handling.
pub fn armored_key_display(public_key: &str) -> String {
    if public_key.is_empty() {
        return String::new();
    }

    let prefix: String = public_key
        .chars()
        .take(6)
        .collect::<String>()
        .to_uppercase();
    // Under 4 chars there is nothing to split.
    if prefix.chars().count() <= 3 {
        return prefix;
    }

    let first: String = prefix.chars().take(3).collect();
    let rest: String = prefix.chars().skip(3).collect();
    format!("{first} {rest}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_first_six_public_key_characters() {
        assert_eq!(
            armored_key_display(
                "027c9c5579cce25013e1e5ae8b4bde6d93bad14457babf5b3e055572ae4931f71"
            ),
            "027 C9C"
        );
        assert_eq!(armored_key_display("abcdef"), "ABC DEF");
        assert_eq!(armored_key_display("abc"), "ABC");
        assert_eq!(armored_key_display(""), "");
    }

    #[test]
    fn short_keys_return_uppercased_prefix_without_space() {
        // length 1-3 → no split.
        assert_eq!(armored_key_display("a"), "A");
        assert_eq!(armored_key_display("ab"), "AB");
        // length 4-5 → split after 3.
        assert_eq!(armored_key_display("abcd"), "ABC D");
        assert_eq!(armored_key_display("abcde"), "ABC DE");
    }
}
