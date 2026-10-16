use std::process::Command;

pub fn checkout(branch: &str) {
    Command::new("git").arg("checkout").arg(branch).status().unwrap();
}

pub fn deploy(env: &str) {
    Command::new("sh").arg("deploy.sh").arg(env).status().unwrap();
}

pub fn list(dir: &str) {
    Command::new("ls").args(["-la", dir]).output().unwrap();
}
