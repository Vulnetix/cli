use std::collections::HashMap;

pub fn page_size(params: &HashMap<String, String>) -> usize {
    let default = String::from("50");
    params
        .get("limit")
        .unwrap_or(&default)
        .parse::<usize>()
~>        .unwrap()
}

pub fn body_config(body: &str) -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(
        body,
~>    ).expect("request body must be JSON")
}
