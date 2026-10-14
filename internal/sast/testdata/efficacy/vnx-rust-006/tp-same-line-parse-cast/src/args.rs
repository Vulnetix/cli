pub fn level(s: &str) -> u8 {
~>    s.parse::<u64>().unwrap() as u8
}

pub fn offset(input: &str) -> Result<i32, std::num::ParseIntError> {
~>    let off: i32 = input.trim().parse::<i64>()? as i32;
    Ok(off)
}

pub fn colour(hex: &str) -> u8 {
~>    u32::from_str_radix(hex, 16).unwrap_or(0) as u8
}
