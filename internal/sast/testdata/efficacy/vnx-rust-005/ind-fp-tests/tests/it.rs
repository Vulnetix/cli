#[test]
fn works() -> Result<(), Box<dyn std::error::Error>> {
    let t = std::fs::read_to_string("fixture.txt").unwrap();
    if t.is_empty() {
        panic!("fixture empty");
    }
    Ok(())
}
