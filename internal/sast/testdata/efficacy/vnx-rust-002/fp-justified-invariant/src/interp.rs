pub fn name(buf: &[u8], end: usize) -> &str {
    if !buf[..end].is_ascii() {
        return "";
    }
    // The bytes were verified to be ASCII above, so this conversion
    // cannot fail.
    let s = std::str::from_utf8(&buf[..end])
        .expect("ascii is utf-8");
    s
}
