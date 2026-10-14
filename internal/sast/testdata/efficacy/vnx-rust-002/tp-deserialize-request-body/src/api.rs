use serde::Deserialize;

#[derive(Deserialize)]
pub struct Order {
    pub id: u64,
}

pub fn handle(body: &str) -> Order {
~>    serde_json::from_str(body).unwrap()
}

pub fn handle_bytes(body: &[u8]) -> Order {
    let order: Order = serde_json::from_slice(body)
~>        .expect("valid order");
    order
}

pub fn load(text: String) -> toml::Value {
~>    toml::from_str(&text).unwrap()
}
