pub fn process(data: &[u8]) -> anyhow::Result<()> {
    if data.is_empty() {
~>        panic!("empty input");
    }
    Ok(())
}
