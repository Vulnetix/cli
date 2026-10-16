pub fn w(s: &str, buffer: &[u8]) -> f64 {
    let a: u32 = s.parse().unwrap();
    let b = a as i64;
    let c = a as f64;
    let l = buffer.len() as u32;
    b as f64 + c + l as f64
}
