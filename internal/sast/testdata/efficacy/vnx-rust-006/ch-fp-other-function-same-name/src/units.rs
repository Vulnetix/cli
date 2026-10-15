pub fn parse_count(s: &str) -> u64 {
    let n: u64 = s.parse().unwrap_or(0);
    n
}

pub fn to_short(n: u64) -> u16 {
    n as u16
}
