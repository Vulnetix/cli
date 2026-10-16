use std::sync::Mutex;

pub struct S { inner: Mutex<u32> }

impl S {
    pub fn get(&self) -> Result<u32, String> {
        let g = self.inner.lock().unwrap();
        Ok(*g)
    }
}

pub fn re() -> Result<bool, regex::Error> {
    let r = regex::Regex::new("^[a-z]+$").unwrap();
    Ok(r.is_match("abc"))
}
