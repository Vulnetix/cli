use std::sync::Mutex;

/// Example:
/// let v: u8 = input.parse().unwrap();
pub fn bump(m: &Mutex<u32>, items: &[u32]) -> u32 {
    // serde_json::from_str(&body).unwrap() would panic here
    let mut g = m.lock().unwrap();
    *g += items.first().copied().unwrap_or(0);
    let msg = "call .parse().unwrap() carefully";
    let _ = msg;
    *g
}
