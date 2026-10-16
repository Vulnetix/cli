pub fn page() -> i64 {
~>    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    size as i64
}

pub fn copy(src: &[u8], dst: &mut [u8]) {
    // copy the bytes over
~>    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
    }
}
