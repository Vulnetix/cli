pub fn alloc(w: &str, h: &str) -> Option<Vec<u8>> {
    let width: usize = w.parse().ok()?;
    let height = h.parse::<usize>().ok()?;
    let size = width.checked_mul(height)?.checked_mul(4)?;
    let wrapped = width.wrapping_add(height);
    let sat = height.saturating_sub(1);
    let _ = (wrapped, sat);
    Some(Vec::with_capacity(size))
}
