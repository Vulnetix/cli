pub fn ttl(raw: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let secs: u64 = raw.parse()?;
    log::debug!("ttl {secs}");
~>    Ok(secs as u16)
}

pub fn port(q: &std::collections::HashMap<String, String>) -> u16 {
    let p = q.get("port").map(|s| s.as_str()).unwrap_or("0").parse::<usize>().unwrap_or(0);
~>    let port = p as u16;
    port
}
