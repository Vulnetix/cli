pub fn alloc_size(hdr: [u8; 4], count: &str) -> Option<usize> {
    let len = u32::from_be_bytes(hdr) as usize;
    let n: usize = count.parse().ok()?;
    let bytes = len
        .checked_mul(n)?
        .checked_add(16)?;
    let capped = n.saturating_mul(8);
    Some(bytes.max(capped))
}
