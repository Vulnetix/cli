use std::process::Command;

pub fn copy(src: &str) {
~>    let _ = Command::new("cmd").args(&["/C", &format!("copy {} backup\\", src)]).status();
}

pub fn ps(script: &str) {
~>    Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", script])
        .output()
        .unwrap();
}
