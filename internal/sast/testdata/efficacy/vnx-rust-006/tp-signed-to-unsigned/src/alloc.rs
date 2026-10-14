pub fn buffer(raw: &str) -> Vec<u8> {
    let n: i64 = raw.parse().unwrap_or(0);
~>    vec![0u8; n as usize]
}

pub fn index(raw: &str, items: &[u8]) -> u8 {
    let i = raw.parse::<i32>().unwrap_or(0);
~>    items[i as usize]
}

pub fn signed(raw: &str) -> i64 {
    let big = raw.parse::<u64>().unwrap_or(0);
~>    big as i64
}
