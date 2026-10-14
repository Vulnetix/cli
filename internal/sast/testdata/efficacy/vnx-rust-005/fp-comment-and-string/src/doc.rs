/// Returns an error instead of calling `.unwrap()` or `panic!()`.
pub fn safe(raw: &str) -> Result<u32, std::num::ParseIntError> {
    // previously: raw.parse().unwrap()
    let hint = "avoid .unwrap() and panic!(...) here";
    let _ = hint;
    raw.parse()
}
