pub fn last_index(raw: &str) -> usize {
    let n = raw.parse::<usize>().unwrap_or(0);
~>    n - 1
}

pub fn mask(raw: &str) -> u64 {
    let bits = u32::from_str_radix(raw, 10).unwrap_or(0);
~>    let m = 1u64 << bits;
    m
}
