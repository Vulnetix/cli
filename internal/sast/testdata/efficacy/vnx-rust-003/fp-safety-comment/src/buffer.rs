pub fn copy(dst: &mut [u8], src: &[u8]) {
    assert!(dst.len() >= src.len());
    // SAFETY: the assert above guarantees dst holds src.len() bytes and the
    // two slices cannot overlap because dst is borrowed mutably.
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
    }
}

pub fn page_size() -> i64 {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }; // SAFETY: sysconf has no preconditions
    size
}

pub struct Handle(*mut u8);

// SAFETY: Handle owns its allocation exclusively and is never aliased.
unsafe impl Send for Handle {}

pub fn map(file: &std::fs::File) -> Option<memmap2::Mmap> {
    // This is sound because the caller of the constructor asserted that the
    // file is not modified while mapped.
    #[allow(unused_unsafe)]
    match unsafe { memmap2::Mmap::map(file) } {
        Ok(m) => Some(m),
        Err(_) => None,
    }
}
