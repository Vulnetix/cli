const MAX: usize = 4096;

pub fn bounded(raw: &str) -> Option<usize> {
    let n: usize = raw.parse().ok()?;
    if n > MAX {
        return None;
    }
    Some(n * 2)
}

pub fn clamped(raw: &str) -> usize {
    let n = raw.parse::<usize>().unwrap_or(0).min(100);
    n + 8
}
