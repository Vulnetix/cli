pub fn encode(v: &[u8]) -> Result<String, String> {
    Ok(hex::encode(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let s = encode(&[1, 2]).unwrap();
        let back = hex::decode(&s).expect("decodes");
        assert_eq!(back, vec![1, 2]);
        Ok(())
    }
}
