use serde_json::Value;

pub fn handle(body: &str, token: &str) -> usize {
~>    let v: Value = serde_json::from_str(body).unwrap();
~>    let bytes = base64::decode(token).unwrap();
    v.as_object().map(|o| o.len()).unwrap_or(0) + bytes.len()
}
