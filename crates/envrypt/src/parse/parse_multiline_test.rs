// Pins multiline and split key/value parsing against
// conformance/fixtures/root/.env.multiline.
use super::test_helpers::*;

const EXPECTED_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnNl1tL3QjKp3DZWM0T3u\nLgGJQwu9WqyzHKZ6WIA5T+7zPjO1L8l3S8k8YzBrfH4mqWOD1GBI8Yjq2L1ac3Y/\nbTdfHN8CmQr2iDJC0C6zY8YV93oZB3x0zC/LPbRYpF8f6OqX1lZj5vo2zJZy4fI/\nkKcI5jHYc8VJq+KCuRZrvn+3V+KuL9tF9v8ZgjF2PZbU+LsCy5Yqg1M8f5Jp5f6V\nu4QuUoobAgMBAAE=\n-----END PUBLIC KEY-----";

#[test]
fn parses_multiline_values_and_split_key_value_lines() {
    let out = parse_env(&fixture_src("root/.env.multiline"), &env(&[]));
    assert_eq!(
        value(&out, "MULTI_DOUBLE_QUOTED"),
        "THIS\nIS\nA\nMULTILINE\nSTRING"
    );
    assert_eq!(
        value(&out, "MULTI_SINGLE_QUOTED"),
        "THIS\nIS\nA\nMULTILINE\nSTRING"
    );
    assert_eq!(
        value(&out, "MULTI_BACKTICKED"),
        "THIS\nIS\nA\n\"MULTILINE'S\"\nSTRING"
    );
    // Exact multiline PEM block.
    assert_eq!(value(&out, "MULTI_PEM_DOUBLE_QUOTED"), EXPECTED_PEM);
    // Split key/value lines.
    assert_eq!(value(&out, "SPLIT_KEY_VALUE_LINES"), "split line");
    assert_eq!(
        value(&out, "SPLIT_KEY_VALUE_SPACED_LINES"),
        "split line with spaces"
    );
}
