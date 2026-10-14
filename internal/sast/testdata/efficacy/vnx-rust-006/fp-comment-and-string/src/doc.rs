// let x = s.parse::<u64>().unwrap() as u8; truncates
pub const HINT: &str = "s.parse::<u64>().unwrap() as u8";

/// `n as u16` after `let n: u64 = s.parse()?` truncates silently.
pub fn noop() {}
