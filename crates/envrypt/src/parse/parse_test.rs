// Pins the full parse pipeline against the root .env fixture
// (conformance/fixtures/root/.env). None of the fixture keys are in the
// process env, so parse runs with an empty process-env map.
use super::test_helpers::*;
use super::*;

fn parsed() -> ParseOutput {
  parse_env(&fixture_src("root/.env"), &env(&[]))
}

#[test]
fn parses_the_env_fixture_contract() {
  let out = parsed();
  assert_eq!(value(&out, "BASIC"), "basic");
  assert_eq!(value(&out, "AFTER_LINE"), "after_line");
  assert_eq!(value(&out, "EMPTY"), "");
  assert_eq!(value(&out, "EMPTY_SINGLE_QUOTES"), "");
  assert_eq!(value(&out, "EMPTY_DOUBLE_QUOTES"), "");
  assert_eq!(value(&out, "EMPTY_BACKTICKS"), "");
  assert_eq!(value(&out, "SINGLE_QUOTES"), "single_quotes");
  assert_eq!(value(&out, "SINGLE_QUOTES_SPACED"), "    single quotes    ");
  assert_eq!(value(&out, "DOUBLE_QUOTES"), "double_quotes");
  assert_eq!(value(&out, "DOUBLE_QUOTES_SPACED"), "    double quotes    ");
  assert_eq!(
    value(&out, "DOUBLE_QUOTES_INSIDE_SINGLE"),
    "double \"quotes\" work inside single quotes"
  );
  // $MONGOLAB_PORT is unset, so it expands to empty.
  assert_eq!(
    value(&out, "DOUBLE_QUOTES_WITH_NO_SPACE_BRACKET"),
    "{ port: }"
  );
  assert_eq!(
    value(&out, "SINGLE_QUOTES_INSIDE_DOUBLE"),
    "single 'quotes' work inside double quotes"
  );
  assert_eq!(
    value(&out, "BACKTICKS_INSIDE_SINGLE"),
    "`backticks` work inside single quotes"
  );
  assert_eq!(
    value(&out, "BACKTICKS_INSIDE_DOUBLE"),
    "`backticks` work inside double quotes"
  );
  assert_eq!(value(&out, "BACKTICKS"), "backticks");
  assert_eq!(value(&out, "BACKTICKS_SPACED"), "    backticks    ");
  assert_eq!(
    value(&out, "DOUBLE_QUOTES_INSIDE_BACKTICKS"),
    "double \"quotes\" work inside backticks"
  );
  assert_eq!(
    value(&out, "SINGLE_QUOTES_INSIDE_BACKTICKS"),
    "single 'quotes' work inside backticks"
  );
  assert_eq!(
    value(&out, "DOUBLE_AND_SINGLE_QUOTES_INSIDE_BACKTICKS"),
    "double \"quotes\" and single 'quotes' work inside backticks"
  );
  // Double quotes expand \n escapes; unquoted and single-quoted keep them
  // literal.
  assert_eq!(value(&out, "EXPAND_NEWLINES"), "expand\nnew\nlines");
  assert_eq!(value(&out, "DONT_EXPAND_UNQUOTED"), "dontexpand\\nnewlines");
  assert_eq!(value(&out, "DONT_EXPAND_SQUOTED"), "dontexpand\\nnewlines");
  assert!(!out.parsed.contains_key("COMMENTS"));
  assert_eq!(value(&out, "INLINE_COMMENTS"), "inline comments");
  assert_eq!(
    value(&out, "INLINE_COMMENTS_SINGLE_QUOTES"),
    "inline comments outside of #singlequotes"
  );
  assert_eq!(
    value(&out, "INLINE_COMMENTS_DOUBLE_QUOTES"),
    "inline comments outside of #doublequotes"
  );
  assert_eq!(
    value(&out, "INLINE_COMMENTS_BACKTICKS"),
    "inline comments outside of #backticks"
  );
  assert_eq!(
    value(&out, "INLINE_COMMENTS_SPACE"),
    "inline comments start with a"
  );
  assert_eq!(value(&out, "EQUAL_SIGNS"), "equals==");
  assert_eq!(value(&out, "RETAIN_INNER_QUOTES"), "{\"foo\": \"bar\"}");
  assert_eq!(
    value(&out, "RETAIN_INNER_QUOTES_AS_STRING"),
    "{\"foo\": \"bar\"}"
  );
  assert_eq!(
    value(&out, "RETAIN_INNER_QUOTES_AS_BACKTICKS"),
    "{\"foo\": \"bar's\"}"
  );
  assert_eq!(
    value(&out, "TRIM_SPACE_FROM_UNQUOTED"),
    "some spaced out string"
  );
  assert_eq!(value(&out, "USERNAME"), "therealnerdybeast@example.tld");
  assert_eq!(value(&out, "SPACED_KEY"), "parsed");
}

#[test]
fn parses_a_buffer_into_an_object() {
  let out = parse_env("BUFFER=true", &env(&[]));
  assert_eq!(value(&out, "BUFFER"), "true");
}

#[test]
fn parses_all_line_ending_styles() {
  // Every line-ending style parses identically.
  for src in [
    "SERVER=localhost\rPASSWORD=password\rDB=tests\r",
    "SERVER=localhost\nPASSWORD=password\nDB=tests\n",
    "SERVER=localhost\r\nPASSWORD=password\r\nDB=tests\r\n",
  ] {
    let out = parse_env(src, &env(&[]));
    let entries: Vec<(String, String)> = out.parsed_map().into_iter().collect();
    assert_eq!(
      entries,
      [
        ("SERVER".to_string(), "localhost".to_string()),
        ("PASSWORD".to_string(), "password".to_string()),
        ("DB".to_string(), "tests".to_string()),
      ],
      "line-ending style {src:?}"
    );
  }
}
