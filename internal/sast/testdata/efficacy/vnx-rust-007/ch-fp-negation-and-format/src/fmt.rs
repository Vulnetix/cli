pub fn describe(raw: &str) -> String {
    let delta: i64 = raw.parse().unwrap_or(0);
    let inverted = -delta;
    let label = format!("{}-{} ({})", delta, inverted, "x");
    let parts = vec![delta, inverted];
    format!("{label}: {:?}", parts)
}
