// An unsafe { } block in user code is reported by the linter below.
pub const MSG: &str = "unsafe { ptr::read(p) } is not allowed here";

/// Example: `unsafe fn foo()` must carry a safety section.
pub fn is_unsafe_keyword(word: &str) -> bool {
    word == "unsafe"
}

#![forbid(unsafe_code)]
pub fn unsafe_count(items: &[u8]) -> usize {
    let unsafe_items = items.len();
    unsafe_items
}
