use std::fmt;

pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_vec(&self.x).unwrap();
        write!(f, "{:?}", s)
    }
}

pub fn first_port(list: &str) -> Option<u16> {
    let p: u16 = list.split(',').next()?.parse().unwrap();
    Some(p)
}

pub fn result_set(rows: &[u8]) -> ResultSet {
    let s = std::str::from_utf8(rows).unwrap();
    ResultSet::new(s)
}
