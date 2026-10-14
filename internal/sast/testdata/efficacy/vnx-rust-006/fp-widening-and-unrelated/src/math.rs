pub fn widen(raw: &str) -> i64 {
    let small = raw.parse::<u32>().unwrap_or(0);
    let wide = small as i64;
    let b = raw.parse::<u8>().unwrap_or(0) as u32;
    let f = raw.parse::<i32>().unwrap_or(0) as f64;
    wide + b as i64 + f as i64
}

pub fn bytes(len: usize, data: &[u8]) -> u8 {
    let checksum = data.iter().fold(0u32, |a, b| a + *b as u32);
    (checksum % 256) as u8 + len as u8
}
