pub struct Handle(*mut u8);

/// Writes `count` bytes of `value` starting at `ptr`.
~>pub unsafe fn fill(ptr: *mut u8, value: u8, count: usize) {
    std::ptr::write_bytes(ptr, value, count);
}

~>unsafe impl Send for Handle {}
