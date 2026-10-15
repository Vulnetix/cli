pub struct Ring {
    buf: *mut u32,
    cap: usize,
}

impl Ring {
    pub fn pair(&self, idx: usize) -> (u32, u32) {
        assert!(idx + 1 < self.cap);
        // SAFETY: the assert keeps idx inside the allocation.
        let a = unsafe { *self.buf.add(idx) };
~>        let b = unsafe { *self.buf.add(idx + 1) };
        (a, b)
    }
}
