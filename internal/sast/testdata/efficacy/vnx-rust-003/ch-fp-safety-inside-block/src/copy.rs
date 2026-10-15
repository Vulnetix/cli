pub fn fill(dst: &mut [u8], byte: u8) {
    unsafe {
        // SAFETY: dst is a valid, exclusively borrowed slice of dst.len() bytes.
        std::ptr::write_bytes(dst.as_mut_ptr(), byte, dst.len());
    }
}
