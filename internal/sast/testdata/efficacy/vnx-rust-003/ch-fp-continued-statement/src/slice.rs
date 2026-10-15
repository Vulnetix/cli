pub fn view<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    // SAFETY: the caller hands over a pointer to len initialised bytes that
    // outlive 'a.
    let slice =
        unsafe { std::slice::from_raw_parts(ptr, len) };
    slice
}

pub fn read_at(ptr: *const u32, i: usize) -> u32 {
    // SAFETY: i is below the length the constructor recorded.
    let v = core::hint::black_box(
        unsafe { ptr.add(i).read() },
    );
    v
}
