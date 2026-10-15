pub fn views(ptrs: &[*const u64]) -> Vec<u64> {
~>    ptrs.iter().map(|p| unsafe { **p }).collect()
}

pub fn endpoint(ptr: *const u8) -> u8 {
    let base = "https://example.invalid/api";
~>    let first = unsafe { *ptr }; // see https://doc.rust-lang.org/std/ptr/
    let _ = base;
    first
}

pub fn widen(x: u32) -> f32 {
~>    unsafe { std::mem::transmute::<u32, f32>(x) }
}
