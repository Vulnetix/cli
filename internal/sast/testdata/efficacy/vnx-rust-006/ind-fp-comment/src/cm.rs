pub fn cm(s: &str) {
    // s.parse::<u64>().unwrap() as u8 would truncate
    let msg = "x.parse::<u64>().unwrap() as u8";
    let _ = (s, msg);
}
