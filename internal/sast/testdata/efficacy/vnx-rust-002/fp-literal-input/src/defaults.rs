use regex::Regex;
use url::Url;

const PATTERN: &str = r"^\d{4}$";

pub fn defaults() {
    let port = "8080".parse::<u16>().unwrap();
    let re = Regex::new(r"^[a-z]+$").unwrap();
    let re2 = Regex::new(PATTERN).unwrap();
    let home = Url::parse("https://example.com/").expect("static url");
    let cfg: serde_json::Value = serde_json::from_str(include_str!("defaults.json")).unwrap();
    let addr: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
    drop((port, re, re2, home, cfg, addr));
}
