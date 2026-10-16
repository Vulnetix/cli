pub fn run(raw: &str) -> Result<u64, std::num::ParseIntError> {
    let a = raw.parse::<u64>()?;
    let b = raw.parse::<u64>().unwrap_or(10);
    let c = match serde_json::from_str::<u32>(raw) {
        Ok(v) => v,
        Err(_) => 0,
    };
    Ok(a + b + c as u64)
}
