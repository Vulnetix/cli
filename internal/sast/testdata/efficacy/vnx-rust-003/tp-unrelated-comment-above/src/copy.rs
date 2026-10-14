pub fn copy(dst: &mut [u8], src: &[u8]) {
    // copy the bytes over
~>    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
    }
}
