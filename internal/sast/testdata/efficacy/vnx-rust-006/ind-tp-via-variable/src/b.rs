pub fn alloc(raw: &str) -> Vec<u8> {
    let n: i64 = raw.parse().unwrap_or(0);
~>    vec![0u8; n as usize]
}

pub fn hdr(buf: &[u8; 8]) -> u16 {
    let len = u64::from_be_bytes(*buf);
~>    let short_len = len as u16;
    short_len
}
