/// Writes `count` bytes of `value` starting at `ptr`.
~>pub unsafe fn fill(ptr: *mut u8, value: u8, count: usize) {
    core::ptr::write_bytes(ptr, value, count);
}

~>unsafe fn read_reg(addr: *const u32) -> u32 {
    core::ptr::read_volatile(addr)
}

#[inline]
~>pub(crate) unsafe extern "C" fn callback(arg: *mut libc::c_void) {
    let _ = arg;
}
