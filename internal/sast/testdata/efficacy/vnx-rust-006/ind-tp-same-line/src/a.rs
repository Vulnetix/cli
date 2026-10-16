pub fn a(s: &str, hex: &str) -> u8 {
~>    let x = s.parse::<u64>().unwrap() as u8;
~>    let y = u32::from_str_radix(hex, 16).unwrap_or(0) as u8;
    x ^ y
}
