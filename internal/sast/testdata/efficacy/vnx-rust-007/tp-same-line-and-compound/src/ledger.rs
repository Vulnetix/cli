pub fn sum(entries: &[&str], offset: u32) -> u32 {
    let mut total: u32 = 0;
    for e in entries {
        let amount: u32 = e.parse().unwrap_or(0);
~>        total += amount;
    }
~>    let end = entries[0].parse::<u32>().unwrap_or(0) + offset;
    total + end
}
