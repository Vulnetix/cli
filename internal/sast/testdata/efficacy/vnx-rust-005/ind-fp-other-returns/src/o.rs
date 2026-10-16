use std::fmt;

pub fn find(v: &[u8]) -> Option<u8> {
    let f = std::fs::read("/etc/x").unwrap();
    f.first().copied().or(v.first().copied())
}

pub fn plain(s: &str) -> u32 {
    s.parse().unwrap()
}

impl fmt::Display for Thing {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let n: u32 = "5".parse().unwrap();
        write!(f, "{}", n)
    }
}
