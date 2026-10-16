pub fn double(x: u32) -> u32 { x * 2 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let n = "21".parse::<u32>().unwrap();
        let s = String::from("42");
        let m: u32 = s.parse().unwrap();
        assert_eq!(double(n), m);
    }
}
