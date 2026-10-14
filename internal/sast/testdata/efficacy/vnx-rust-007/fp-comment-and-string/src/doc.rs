// let n = s.parse::<u32>()?; n + 1 may overflow
pub const NOTE: &str = "let total = len + HEADER_LEN;";

/// `width * height` overflows when both come from `parse::<usize>()`.
pub fn noop() {}
