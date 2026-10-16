use std::path::Path;

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
~>    let cfg: Config = toml::from_str(&text).unwrap();
    Ok(cfg)
}

pub fn save(path: &Path, body: &[u8]) -> std::io::Result<()> {
~>    let mut f = std::fs::File::create(path).expect("create output");
    std::io::Write::write_all(&mut f, body)
}
