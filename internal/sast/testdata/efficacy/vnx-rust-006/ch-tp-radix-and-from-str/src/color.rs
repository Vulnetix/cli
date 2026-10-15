use std::str::FromStr;

pub fn channel(hex: &str) -> u8 {
~>    u32::from_str_radix(hex, 16).unwrap_or(0) as u8
}

pub fn level(v: &str) -> u32 {
    let mut n = i32::from_str(v).unwrap_or_default();
    n += 1;
~>    n as u32
}
