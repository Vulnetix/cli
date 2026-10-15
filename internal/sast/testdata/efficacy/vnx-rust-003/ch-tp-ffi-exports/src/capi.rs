use std::ffi::{c_char, CStr};

#[no_mangle]
~>pub unsafe extern "C" fn widget_name_len(name: *const c_char) -> usize {
    CStr::from_ptr(name).to_bytes().len()
}

/// Frees a buffer returned by `widget_alloc`.
#[no_mangle]
~>pub(crate) unsafe fn widget_free(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, len, len));
}

pub struct Shared(*const u8);

~>unsafe impl Sync for Shared {}
