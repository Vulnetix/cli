use std::process::Command;

pub fn convert(input: &str, output: &str) {
    let line = format!("convert {} {}", input, output);
~>    let _ = Command::new("sh").args(["-c", &line]).output();
}

pub fn win_copy(src: &str) {
~>    let _ = Command::new("cmd").args(&["/C", &format!("copy {} backup\\", src)]).output();
}

pub fn ps(filter: &str) {
~>    let _ = Command::new("powershell")
        .args(vec!["-Command", filter])
        .output();
}
