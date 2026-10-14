#[test]
fn roundtrip() {
    let text = std::fs::read_to_string("tests/data/a.json").unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(v.is_object());
}
