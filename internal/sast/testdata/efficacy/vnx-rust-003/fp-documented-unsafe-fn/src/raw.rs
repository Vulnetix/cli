/// Writes `count` bytes of `value` starting at `ptr`.
///
/// # Safety
///
/// `ptr` must be valid for writes of `count` bytes.
pub unsafe fn fill(ptr: *mut u8, value: u8, count: usize) {
    core::ptr::write_bytes(ptr, value, count);
}

/// Returns a memory-map strategy.
///
/// The caller guarantees that the underlying file won't be mutated while
/// it is mapped; otherwise reading it is undefined behaviour.
#[inline]
pub unsafe fn auto() -> u8 {
    1
}
