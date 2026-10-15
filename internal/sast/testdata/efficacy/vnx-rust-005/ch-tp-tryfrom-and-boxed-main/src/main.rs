use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;

pub struct Level(u8);

impl TryFrom<&str> for Level {
    type Error = String;

    fn try_from(v: &str) -> Result<Self, Self::Error> {
        match v {
            "low" => Ok(Level(1)),
            "high" => Ok(Level(3)),
~>            other => panic!("unknown level {other}"),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
~>    let mut f = File::open("settings.toml").unwrap();
    let mut s = String::new();
~>    f.read_to_string(&mut s).expect("read settings");
    Ok(())
}
