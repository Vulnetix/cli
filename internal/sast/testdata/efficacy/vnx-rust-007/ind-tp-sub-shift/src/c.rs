pub fn d(raw: &str, offset: u32) -> u64 {
~>    let z = raw.parse::<u32>().unwrap_or(0) + offset;
    let n = raw.parse::<usize>().unwrap_or(0);
~>    let k = n - 1;
    let bits = u32::from_str_radix(raw, 10).unwrap_or(0);
~>    let m = 1u64 << bits;
    m + k as u64 + z as u64
}
