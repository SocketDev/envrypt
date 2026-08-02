// Pins variable expansion against conformance/fixtures/root/.env.expand. The
// pipeline runs with an injected process-env map; nothing mutates the real
// environment.
use super::test_helpers::*;
use super::*;

fn expand_fixture(process_env: &IndexMap<String, String>, overload: bool) -> ParseOutput {
    let src = fixture_src("root/.env.expand");
    let mut opts = ParseOptions::new(process_env);
    opts.overload = overload;
    parse_with_ring(&src, &opts)
}

#[test]
fn expands() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "BASIC"), "basic");
    assert_eq!(value(&out, "BASIC_EXPAND"), "basic");
    assert_eq!(value(&out, "MACHINE_EXPAND"), "file");
}

#[test]
fn expands_using_the_machine_value_first_if_it_exists() {
    let out = expand_fixture(&env(&[("MACHINE", "machine")]), false);
    assert_eq!(value(&out, "MACHINE"), "machine");
    assert_eq!(value(&out, "MACHINE_EXPAND"), "machine");
}

#[test]
fn expands_to_bring_own_process_env() {
    // The injected map is caller-owned, so this asserts the parsed values.
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "BASIC"), "basic");
    assert_eq!(value(&out, "BASIC_EXPAND"), "basic");
    assert_eq!(value(&out, "MACHINE_EXPAND"), "file");
    assert_eq!(out.injected.get("BASIC").unwrap().last().unwrap(), "basic");
    assert!(out.existed.is_empty());
}

#[test]
fn expands_env_expand_correctly() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "ESCAPED_EXPAND"), "$ESCAPED");
    assert_eq!(value(&out, "EXPAND_DEFAULT"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED2"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED_TWICE"), "filedefault");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED_TWICE2"), "filedefault");
    assert_eq!(value(&out, "EXPAND_DEFAULT_SPECIAL_CHARACTERS"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_SPECIAL_CHARACTERS2"), "file");
    assert_eq!(value(&out, "UNDEFINED_EXPAND"), "");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_NESTED"), "file");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT"), "default");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT2"), "default");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED"), "default");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED2"), "default");
    assert_eq!(
        value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED_TWICE"),
        "default"
    );
    assert_eq!(
        value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED_TWICE2"),
        "default"
    );
    assert_eq!(
        value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS"),
        "/default/path:with/colon"
    );
    assert_eq!(
        value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS2"),
        "/default/path:with/colon"
    );
    assert_eq!(
        value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS_NESTED"),
        "/default/path:with/colon"
    );
    assert_eq!(
        value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS_NESTED2"),
        "/default/path:with/colon"
    );
    assert_eq!(
        value(
            &out,
            "NO_CURLY_BRACES_UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS"
        ),
        ":-/default/path:with/colon"
    );
    assert_eq!(
        value(
            &out,
            "NO_CURLY_BRACES_UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS2"
        ),
        "-/default/path:with/colon"
    );
}

#[test]
fn expands_env_expand_correctly_when_machine_already_set() {
    let out = expand_fixture(&env(&[("MACHINE", "machine")]), false);
    assert_eq!(value(&out, "ESCAPED_EXPAND"), "$ESCAPED");
    assert_eq!(value(&out, "EXPAND_DEFAULT"), "machine");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED"), "machine");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED2"), "machine");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED_TWICE"), "machinedefault");
    assert_eq!(
        value(&out, "EXPAND_DEFAULT_NESTED_TWICE2"),
        "machinedefault"
    );
    assert_eq!(value(&out, "EXPAND_DEFAULT_SPECIAL_CHARACTERS"), "machine");
    assert_eq!(value(&out, "EXPAND_DEFAULT_SPECIAL_CHARACTERS2"), "machine");
    assert_eq!(value(&out, "UNDEFINED_EXPAND"), "");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_NESTED"), "machine");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT"), "default");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT2"), "default");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED"), "default");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED2"), "default");
    assert_eq!(
        value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED_TWICE"),
        "default"
    );
    assert_eq!(
        value(&out, "UNDEFINED_EXPAND_DEFAULT_NESTED_TWICE2"),
        "default"
    );
    assert_eq!(
        value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS"),
        "/default/path:with/colon"
    );
    assert_eq!(
        value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS2"),
        "/default/path:with/colon"
    );
    assert_eq!(
        value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS_NESTED"),
        "/default/path:with/colon"
    );
    assert_eq!(
        value(&out, "UNDEFINED_EXPAND_DEFAULT_SPECIAL_CHARACTERS_NESTED2"),
        "/default/path:with/colon"
    );
}

#[test]
fn expands_correctly_when_machine_set_but_overload_true() {
    let out = expand_fixture(&env(&[("MACHINE", "machine")]), true);
    assert_eq!(value(&out, "MACHINE"), "file");
    assert_eq!(value(&out, "MACHINE_EXPAND"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED2"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED_TWICE"), "filedefault");
    assert_eq!(value(&out, "EXPAND_DEFAULT_NESTED_TWICE2"), "filedefault");
    assert_eq!(value(&out, "EXPAND_DEFAULT_SPECIAL_CHARACTERS"), "file");
    assert_eq!(value(&out, "EXPAND_DEFAULT_SPECIAL_CHARACTERS2"), "file");
    assert_eq!(value(&out, "UNDEFINED_EXPAND"), "");
    assert_eq!(value(&out, "UNDEFINED_EXPAND_NESTED"), "file");
}

#[test]
fn expands_mongo_real_world_example() {
    let out = expand_fixture(&env(&[]), false);
    let uri = "mongodb://username:password@abcd1234.mongolab.com:12345/heroku_db";
    assert_eq!(value(&out, "MONGOLAB_URI"), uri);
    assert_eq!(value(&out, "MONGOLAB_URI_RECURSIVELY"), uri);
    assert_eq!(value(&out, "NO_CURLY_BRACES_URI"), uri);
    assert_eq!(value(&out, "NO_CURLY_BRACES_URI_RECURSIVELY"), uri);
}

#[test]
fn expands_with_periods_in_key_name() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "POSTGRESQL.MAIN.USER"), "postgres");
}

#[test]
fn does_not_expand_dollar() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "DOLLAR"), "$");
}

#[test]
fn handles_one_two() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "ONETWO"), "onetwo");
    assert_eq!(value(&out, "ONETWO_SIMPLE"), "onetwo");
    assert_eq!(value(&out, "ONETWO_SIMPLE2"), "onetwo");
    assert_eq!(value(&out, "ONETWO_SUPER_SIMPLE"), "onetwo");
}

#[test]
fn handles_two_dollar_signs() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(
        value(&out, "TWO_DOLLAR_SIGNS_FOLLOWED_BY_DIGIT"),
        "abcd$$1234foo"
    );
    assert_eq!(value(&out, "TWO_DOLLAR_SIGNS_FOLLOWED_BY_LETTER"), "pa$@");
    assert_eq!(
        value(&out, "TWO_DOLLAR_SIGNS_FOLLOWED_BY_LETTER_SINGLE_QUOTE"),
        "pa$$word@"
    );
}

#[test]
fn does_not_choke() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(
        value(&out, "DONT_CHOKE1"),
        ".kZh`>4[,[DDU-*Jt+[;8-,@K=,9%;F9KsoXqOE)gpG^X!{)Q+/9Fc(QF}i[NEi!"
    );
    assert_eq!(
        value(&out, "DONT_CHOKE2"),
        r"=;+=CNy3)-D=zI6gRP2w\$B@0K;Y]e^EFnCmx\$Dx?;.9wf-rgk1BcTR0]JtY<S:b_"
    );
    assert_eq!(
        value(&out, "DONT_CHOKE3"),
        "MUcKSGSY@HCON<1S_siWTP`DgS*Ug],mu]SkqI|7V2eOk9:>&fw;>HEwms`D8E2H"
    );
    assert_eq!(
        value(&out, "DONT_CHOKE4"),
        "m]zjzfRItw2gs[2:{p{ugENyFw9m)tH6_VCQzer`*noVaI<vqa3?FZ9+6U;K#Bfd"
    );
    assert_eq!(
        value(&out, "DONT_CHOKE5"),
        "#la__nK?IxNlQ%`5q&DpcZ>Munx=[1-AMgAcwmPkToxTaB?kgdF5y`A8m=Oa-B!)"
    );
    assert_eq!(
        value(&out, "DONT_CHOKE6"),
        r"xlC&*<j4J<d._<JKH0RBJV!4(ZQEN-+&!0p137<g*hdY2H4xk?/;KO1\$(W{:Wc}Q"
    );
    assert_eq!(
        value(&out, "DONT_CHOKE7"),
        r"?\$6)m*xhTVewc#NVVgxX%eBhJjoHYzpXFg=gzn[rWXPLj5UWj@z\$/UDm8o79n/p%"
    );
    assert_eq!(
        value(&out, "DONT_CHOKE8"),
        "@}:[4#g%[R-CFR});bY(Z[KcDQDsVn2_y4cSdU<Mjy!c^F`G<!Ks7]kbS]N1:bP:"
    );
}

#[test]
fn expands_domain_with_host() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "HOST"), "something");
    assert_eq!(value(&out, "DOMAIN"), "https://something");
}

#[test]
fn does_not_expand_single_quote() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "SINGLE_QUOTE"), "$BASIC");
}

#[test]
fn handles_deep_nesting() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(
        value(&out, "DEEP8"),
        "prefix5-prefix4-prefix3-prefix2-prefix1-basic-suffix1-suffix2-suffix3-suffix4-suffix5"
    );
}

#[test]
fn handles_self_referencing() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "EXPAND_SELF"), "");
    assert_eq!(value(&out, "DEEP_SELF"), "basic-bar");
    assert_eq!(value(&out, "DEEP_SELF_PRIOR"), "prefix2-foo-suffix2");
}

#[test]
fn handles_progressive_updating() {
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "PROGRESSIVE"), "first-second");
}

#[test]
fn single_quote_expansion_bug_test_cases() {
    // Single-quote expansion regressions (issues #422/#674).
    let out = expand_fixture(&env(&[]), false);
    assert_eq!(value(&out, "PGUSER"), "user");
    assert_eq!(value(&out, "PGHOST"), "localhost");
    assert_eq!(
        value(&out, "DATABASE_URL"),
        "postgres://user@localhost/my_database"
    );
    assert_eq!(value(&out, "PGUSER2"), "user");
    assert_eq!(value(&out, "PGHOST2"), "localhost");
    assert_eq!(
        value(&out, "DATABASE_URL2"),
        "postgres://user@localhost/my_database"
    );
    assert_eq!(value(&out, "PGUSER3"), "user");
    assert_eq!(value(&out, "PGHOST3"), "localhost");
    assert_eq!(
        value(&out, "DATABASE_URL3"),
        "postgres://user@localhost/my_database"
    );
    assert_eq!(value(&out, "PGUSER4"), "user");
    assert_eq!(value(&out, "PGHOST4"), "localhost");
    assert_eq!(
        value(&out, "DATABASE_URL4"),
        "postgres://user@localhost/my_database"
    );
    assert_eq!(value(&out, "PGUSER5"), "user");
    assert_eq!(value(&out, "PGHOST5"), "localhost");
    assert_eq!(
        value(&out, "DATABASE_URL5"),
        "postgres://user@localhost/my_database"
    );
}
