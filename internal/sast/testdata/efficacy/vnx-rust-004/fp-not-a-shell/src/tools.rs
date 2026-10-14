use std::process::Command;

pub fn ping(host: &str) {
    let _ = Command::new("ping").arg("-c").arg("1").arg(host).output();
}

pub fn gitdir(dir: &str) {
    let _ = Command::new("git").arg(format!("--git-dir={}", dir)).arg("status").output();
    let _ = Command::new(format!("{}/bin/rustfmt", env!("CARGO_HOME"))).arg("--check").status();
}

pub fn grep(pattern: &str, file: &str) {
    let _ = Command::new("grep").args(["-c", pattern, file]).output();
}
