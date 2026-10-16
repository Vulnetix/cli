use std::process::Command;

const BOOTSTRAP: &str = "make -j4 all";

pub fn a() {
    Command::new("sh").arg("-c").arg("sync").status().unwrap();
}

pub fn b() {
    Command::new("sh").arg("-c").arg(BOOTSTRAP).status().unwrap();
}
