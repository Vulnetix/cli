pub fn grow(v: &[u8], extra: usize) -> usize {
    let len = v.len();
    let size = len + extra;
    let count = 3;
    size * count
}

pub fn scale(raw: &str) -> f64 {
    let f: f64 = raw.parse().unwrap_or(1.0);
    let ratio = raw.parse::<f32>().unwrap_or(1.0);
    f * 2.0 + ratio as f64
}

pub fn label(raw: &str) -> String {
    let name: String = raw.parse().unwrap();
    name + "-suffix"
}
