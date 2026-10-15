pub struct Sample {
    pub n: i64,
}

pub fn widen(s: &str, sample: &Sample) -> (i64, f64, u16) {
    let small: u32 = s.parse().unwrap_or(0);
    let ratio: f64 = s.parse().unwrap_or(0.0);
    let wide = small as i64;
    let scaled = small as f64 / 2.0;
    let trunc = ratio as u16;
    let _ = sample.n as u16;
    (wide, scaled, trunc)
}
