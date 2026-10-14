pub fn parse(s: &str) -> Option<u32> {
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let input = String::from("42");
        let v: u32 = input.parse().unwrap();
        let j: serde_json::Value = serde_json::from_str(&input).unwrap();
        assert_eq!(parse(&input), Some(v));
        drop(j);
    }
}
