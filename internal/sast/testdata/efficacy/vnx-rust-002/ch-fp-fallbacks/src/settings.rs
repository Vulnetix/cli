use std::env;

const DEFAULT_ADDR: &str = "0.0.0.0:8080";

pub fn port() -> u16 {
    env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080)
}

pub fn workers() -> usize {
    env::var("WORKERS").unwrap_or_default().parse::<usize>().unwrap_or(4)
}

pub fn addr() -> std::net::SocketAddr {
    DEFAULT_ADDR.parse().unwrap()
}

pub fn timeout(raw: &str) -> u64 {
    match raw.parse::<u64>() {
        Ok(v) => v,
        Err(_) => 30,
    }
}

pub fn label() -> String {
    let msg = "call s.parse::<u32>().unwrap() only in tests";
    msg.to_string()
}
