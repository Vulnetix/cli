pub fn port(raw: &str) -> Option<u16> {
    let n: u64 = raw.parse().ok()?;
    match n {
        1..=65535 => Some(n as u16),
        _ => None,
    }
}

pub fn small(raw: &str) -> Option<u8> {
    let v = raw.parse::<i64>().ok()?;
    if !matches!(v, 0..=255) {
        return None;
    }
    Some(v as u8)
}
