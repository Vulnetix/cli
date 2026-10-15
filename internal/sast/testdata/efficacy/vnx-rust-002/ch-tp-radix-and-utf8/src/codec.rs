pub fn color(hex: &str) -> u32 {
~>    u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap()
}

pub fn name(buf: &[u8], n: usize) -> &str {
~>    std::str::from_utf8(&buf[..n]).expect("utf8 name")
}

pub fn blob(encoded: &str) -> Vec<u8> {
    use base64::Engine;
~>    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded.as_bytes()).unwrap();
    bytes
}
