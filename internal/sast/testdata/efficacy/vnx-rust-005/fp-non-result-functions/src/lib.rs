pub fn checked(path: &str) -> Result<String, std::io::Error> {
    let s = std::fs::read_to_string(path)?;
    Ok(s)
}

pub fn first_byte(v: &[u8]) -> u8 {
    *v.first().unwrap()
}

pub fn port(raw: &str) -> Option<u16> {
    let p = raw.parse::<u16>().ok()?;
    Some(p)
}

fn main() {
    let cfg = checked("app.toml").expect("config");
    println!("{cfg}");
}

pub fn outer() -> Result<(), String> {
    fn inner(v: &[u8]) -> u8 {
        v[0]
    }
    let _ = inner(&[1]);
    Ok(())
}
