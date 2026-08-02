use super::*;

pub(super) fn env_map(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub(super) fn fixture(rel: &str) -> String {
    test_support::fixture_path(rel)
        .to_string_lossy()
        .into_owned()
}

pub(super) fn quiet_logger() -> (test_support::LoggerCapture, Logger) {
    let cap = test_support::LoggerCapture::new();
    let logger = Logger::new(
        Box::new(cap.stdout_writer()),
        Box::new(cap.stderr_writer()),
        1,
    );
    (cap, logger)
}
