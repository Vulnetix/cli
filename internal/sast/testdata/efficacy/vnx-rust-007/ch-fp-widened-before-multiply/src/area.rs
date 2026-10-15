pub fn pixels(w: &str, h: &str) -> Option<u64> {
    let width: u32 = w.parse().ok()?;
    let height: u32 = h.parse().ok()?;
    let total = (width as u64) * (height as u64);
    Some(total)
}
