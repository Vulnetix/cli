use std::net::IpAddr;

pub fn loopback() -> IpAddr {
    "127.0.0.1".parse::<IpAddr>().unwrap()
}

pub fn re() -> regex::Regex {
    regex::Regex::new("^[a-z]+$").unwrap()
}

const DEFAULT_PORT: &str = "8080";
pub fn port() -> u16 {
    DEFAULT_PORT.parse().unwrap()
}
