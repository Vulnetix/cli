pub fn alloc(w: &str, h: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    let width: usize = w.parse()?;
    let height = h.parse::<usize>()?;
~>    let buf = Vec::with_capacity(width * height * 4);
    Ok(buf)
}

pub fn pixels(raw: &str) -> Vec<u32> {
    let count = raw.trim().parse::<u32>().unwrap_or(1);
~>    vec![0; (count * 3) as usize]
}
