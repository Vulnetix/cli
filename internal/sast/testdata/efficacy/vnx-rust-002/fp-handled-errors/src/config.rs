pub fn parse(raw: &str, body: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let port: u16 = raw.trim().parse()?;
    let workers = raw.parse::<usize>().unwrap_or(4);
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let n: u32 = raw.parse().unwrap_or_else(|_| 1);
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(_) => {}
        Err(e) => return Err(e.into()),
    }
    let _ = (workers, v, n);
    Ok(port)
}
