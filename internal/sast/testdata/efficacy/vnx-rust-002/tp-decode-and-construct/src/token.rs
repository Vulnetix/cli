use regex::Regex;
use url::Url;

pub fn decode(token: &str, buf: Vec<u8>, raw: &str, pattern: &str) {
~>    let bytes = base64::decode(token).unwrap();
~>    let text = String::from_utf8(buf).unwrap();
~>    let key = hex::decode(raw).expect("hex key");
~>    let target = Url::parse(raw).unwrap();
~>    let re = Regex::new(pattern).unwrap();
~>    let id = uuid::Uuid::parse_str(&text).unwrap();
    drop((bytes, key, target, re, id));
}
