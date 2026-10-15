use std::process::Command;

pub fn run_ps(script: &str) -> std::io::Result<std::process::Output> {
~>    Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
}

pub fn run_strict(line: String) -> std::io::Result<std::process::ExitStatus> {
~>    Command::new("/bin/bash").arg("-e").arg("-c").arg(&line).status()
}
