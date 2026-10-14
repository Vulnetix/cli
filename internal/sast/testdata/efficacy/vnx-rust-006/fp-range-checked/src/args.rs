use std::convert::TryFrom;

pub fn level(s: &str) -> Option<u8> {
    let v = s.parse::<u64>().ok()?;
    u8::try_from(v).ok()
}

pub fn ttl(raw: &str) -> Result<u16, String> {
    let secs: u64 = raw.parse().map_err(|_| "bad")?;
    if secs > u16::MAX as u64 {
        return Err("too large".into());
    }
    Ok(secs as u16)
}

pub fn buffer(raw: &str) -> Vec<u8> {
    let n: i64 = raw.parse().unwrap_or(0);
    let n = n.clamp(0, 4096);
    vec![0u8; n as usize]
}

pub fn pct(raw: &str) -> u8 {
    let p = raw.parse::<u32>().unwrap_or(0);
    p.min(100) as u8
}
