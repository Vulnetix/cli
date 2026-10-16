pub fn nd(v: &[u8], a: f64, name: &str) -> String {
    let n = v.len() + 4;
    let f = a * 2.5 + 1.0;
    // let x = s.parse::<u32>().unwrap(); x + 1
    let s = "width * height + 1";
    format!("{}{}{}{}", n, f, s, name)
}
