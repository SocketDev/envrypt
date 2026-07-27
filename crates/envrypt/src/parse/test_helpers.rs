use super::*;

pub(super) fn env(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
  pairs
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

pub(super) fn parse_env(src: &str, process_env: &IndexMap<String, String>) -> ParseOutput {
  parse_with_ring(src, &ParseOptions::new(process_env))
}

pub(super) fn value<'a>(out: &'a ParseOutput, key: &str) -> &'a str {
  out
    .parsed
    .get(key)
    .unwrap_or_else(|| panic!("key {key:?} missing from parsed"))
    .last()
    .unwrap()
}

pub(super) fn fixture_src(rel: &str) -> String {
  let path = test_support::fixture_path(rel);
  std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}
