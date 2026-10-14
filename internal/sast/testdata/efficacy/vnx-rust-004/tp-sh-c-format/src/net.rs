use std::process::Command;

pub fn ping(host: &str) -> std::io::Result<std::process::Output> {
~>    Command::new("sh").arg("-c").arg(format!("ping -c 1 {}", host)).output()
}

pub fn lookup(name: &str) {
~>    let _ = std::process::Command::new("/bin/bash").arg("-c").arg(format!("dig +short {name}")).status();
}
