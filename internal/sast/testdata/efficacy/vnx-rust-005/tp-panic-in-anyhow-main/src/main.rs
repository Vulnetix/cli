fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
~>        panic!("usage: tool <file>");
    }
    let data = std::fs::read(&args[1])?;
    process(&data)
}

fn process(data: &[u8]) -> anyhow::Result<()> {
    if data.is_empty() {
~>        panic!("empty input");
    }
    Ok(())
}
