#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

// we avoid unsafe code entirely here
/// This module has no unsafe blocks.
pub fn msg() -> &'static str {
    "this is not unsafe { really }"
}

pub fn unsafe_count() -> usize {
    let unsafe_total = 0;
    unsafe_total
}
