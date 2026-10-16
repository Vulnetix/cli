use std::convert::TryFrom;

pub fn ck(s: &str) -> Result<u8, Box<dyn std::error::Error>> {
    let n = s.parse::<u64>()?;
    let small = u8::try_from(n)?;
    Ok(small)
}

pub fn ranged(s: &str) -> Option<u16> {
    let n: u64 = s.parse().ok()?;
    if n > 65535 {
        return None;
    }
    Some(n as u16)
}
