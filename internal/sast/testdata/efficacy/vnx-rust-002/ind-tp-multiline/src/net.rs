pub fn parse_url(input: &str) -> url::Url {
    url::Url::parse(input)
~>        .unwrap()
}

pub fn pat(pattern: &str) -> regex::Regex {
~>    regex::Regex::new(pattern).expect("bad pattern")
}
