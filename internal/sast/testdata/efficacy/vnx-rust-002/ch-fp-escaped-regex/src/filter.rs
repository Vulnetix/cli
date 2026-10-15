use regex::Regex;

pub fn exact_word(name: &str) -> Regex {
    Regex::new(&format!(r"\b{}\b", regex::escape(name))).unwrap()
}

pub fn prefix(name: &str) -> Regex {
    let escaped = regex::escape(name);
    Regex::new(&format!("^{}", escaped)).expect("escaped pattern is valid")
}
