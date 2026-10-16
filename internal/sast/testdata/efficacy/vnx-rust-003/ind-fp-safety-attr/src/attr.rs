/// Reads one byte.
///
/// # Safety
/// `p` must be non-null and point to a readable byte.
#[inline]
#[must_use]
pub unsafe fn peek(p: *const u8) -> u8 {
    // SAFETY: documented in the function contract above.
    unsafe { *p }
}
