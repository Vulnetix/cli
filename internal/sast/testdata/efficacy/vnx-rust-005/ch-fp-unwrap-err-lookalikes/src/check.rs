pub fn validate(raw: &str) -> Result<u32, String> {
    let err = raw.parse::<u32>().unwrap_err();
    let n = raw.parse::<u32>().unwrap_or_default();
    let m = raw.trim().parse::<u32>().map_err(|e| e.to_string())?;
    let msg = "never call .unwrap() on request data";
    // let bad = raw.parse::<u32>().unwrap();
    let _ = (err, msg);
    Ok(n + m)
}
