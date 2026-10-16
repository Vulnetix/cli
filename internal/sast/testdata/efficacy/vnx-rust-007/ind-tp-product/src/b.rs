pub fn buf(w: &str, h: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    let width: usize = w.parse()?;
    let height = h.parse::<usize>()?;
~>    Ok(Vec::with_capacity(width * height * 4))
}
