pub fn body(buf: &[u8], total: usize) -> &[u8] {
    let off = 6usize;
    let len = u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;
~>    let remaining = total - len;
    let _ = remaining;
~>    &buf[off..off + len]
}
