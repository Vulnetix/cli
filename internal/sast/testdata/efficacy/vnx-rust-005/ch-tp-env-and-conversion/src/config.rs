use std::convert::TryInto;
use std::env;

pub struct Config {
    pub url: String,
    pub shards: u16,
}

pub fn from_env() -> anyhow::Result<Config> {
~>    let url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let raw: u64 = env::var("SHARDS")?.parse()?;
~>    let shards: u16 = raw.try_into().unwrap();
    Ok(Config { url, shards })
}
