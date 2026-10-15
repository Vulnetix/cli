pub fn buffer(query: &std::collections::HashMap<String, String>) -> Vec<u8> {
    let size: i64 = query
        .get("size")
        .map(|s| s.as_str())
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
~>    vec![0u8; size as usize]
}

pub fn offset(arg: &str) -> isize {
~>    let raw = arg.trim().parse::<isize>().expect("offset") as usize;
    raw as isize
}
