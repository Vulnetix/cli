pub fn ok() -> Result<(), String> { Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;

    fn helper() -> Result<u32, std::num::ParseIntError> {
        let n = std::fs::read_to_string("x").unwrap();
        Ok(n.parse::<u32>().unwrap())
    }
}
