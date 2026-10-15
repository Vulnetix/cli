use std::net::IpAddr;
use axum::http::HeaderMap;

pub fn client_ip(headers: &HeaderMap) -> IpAddr {
    let raw = headers.get("x-forwarded-for").map(|v| v.to_str().unwrap_or("")).unwrap_or("");
~>    let ip: IpAddr = raw.split(',').next().unwrap_or("").trim().parse().unwrap();
    ip
}

pub fn token_id(token: &str) -> uuid::Uuid {
~>    uuid::Uuid::parse_str(&token[7..]).unwrap()
}
