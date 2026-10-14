use std::process::Command;

pub fn checkout(branch: &str) {
~>    let mut cmd = Command::new("sh");
    cmd.arg("-c");
    cmd.arg("git checkout ".to_owned() + branch);
    let _ = cmd.status();
}
