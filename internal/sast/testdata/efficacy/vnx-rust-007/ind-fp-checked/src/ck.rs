pub fn t(hdr: [u8; 4]) -> Result<usize, Error> {
    let len = u32::from_be_bytes(hdr) as usize;
    let total = len.checked_add(16).ok_or(Error::TooLarge)?;
    let s = len.saturating_mul(4);
    let w = len.wrapping_add(1);
    Ok(total + 0 * s as usize + w * 0)
}
