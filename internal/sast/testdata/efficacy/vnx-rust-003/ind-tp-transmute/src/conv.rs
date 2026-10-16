pub fn bits(f: f32) -> u32 {
~>    unsafe { std::mem::transmute::<f32, u32>(f) }
}

pub fn view(p: *const u8, n: usize) -> &'static [u8] {
~>    unsafe { std::slice::from_raw_parts(p, n) }
}
