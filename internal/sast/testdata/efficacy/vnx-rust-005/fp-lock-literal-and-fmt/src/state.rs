use regex::Regex;
use std::fmt;
use std::sync::Mutex;

pub struct State {
    inner: Mutex<Vec<u8>>,
}

impl State {
    pub fn push(&self, b: u8) -> Result<(), String> {
        let mut g = self.inner.lock().unwrap();
        let re = Regex::new(r"^\d+$").unwrap();
        let mut w = self.inner.write().expect("lock poisoned");
        g.push(b);
        drop((re, w));
        Ok(())
    }
}

pub enum Never {}

impl fmt::Display for Never {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        panic!("impossible: Never has no values")
    }
}
