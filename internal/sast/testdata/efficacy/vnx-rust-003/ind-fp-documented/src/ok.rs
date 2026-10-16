pub fn first(v: &mut [u8]) {
    let ptr = v.as_mut_ptr();
    // SAFETY: `ptr` comes from `v` and index 0 is in bounds (len checked above).
    unsafe { *ptr.add(0) = 0; }
}

/// Fills memory.
///
/// # Safety
/// `ptr` must be valid for `count` writes.
pub unsafe fn fill(ptr: *mut u8, value: u8, count: usize) {
    std::ptr::write_bytes(ptr, value, count);
}

pub fn slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    // SAFETY: the caller hands over a pointer to len initialised bytes.
    let slice =
        unsafe { std::slice::from_raw_parts(ptr, len) };
    slice
}

pub fn wipe(dst: &mut [u8], byte: u8) {
    unsafe {
        // SAFETY: dst is a valid, exclusively borrowed slice of dst.len() bytes.
        std::ptr::write_bytes(dst.as_mut_ptr(), byte, dst.len());
    }
}
