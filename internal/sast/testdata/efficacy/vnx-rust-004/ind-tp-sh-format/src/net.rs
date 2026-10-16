use std::process::Command;

pub fn ping(host: &str) {
~>    let _ = Command::new("sh").arg("-c").arg(format!("ping -c 1 {}", host)).output();
}

pub fn convert(input: &str, output: &str) {
    let line = format!("convert {} {}", input, output);
~>    let _ = Command::new("bash").args(["-c", &line]).output();
}
