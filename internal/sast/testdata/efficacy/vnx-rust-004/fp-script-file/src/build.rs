use std::process::Command;

pub fn build(target: &str) {
    let _ = Command::new("sh").arg("scripts/build.sh").arg(target).status();
    let _ = Command::new("bash").args(["scripts/deploy.sh", target]).status();
}
