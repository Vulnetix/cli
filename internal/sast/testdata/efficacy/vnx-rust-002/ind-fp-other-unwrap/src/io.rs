use std::sync::Mutex;

pub fn read(m: &Mutex<Vec<u8>>) -> usize {
    let g = m.lock().unwrap();
    let f = std::fs::File::open("/etc/hostname").unwrap();
    // let x = input.parse::<u32>().unwrap();
    let _ = f;
    g.len()
}
