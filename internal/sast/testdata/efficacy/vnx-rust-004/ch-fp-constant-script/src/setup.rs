use std::process::Command;

const BOOTSTRAP: &str = "set -eu; mkdir -p /var/lib/app && chown app /var/lib/app";

pub fn bootstrap() -> std::io::Result<std::process::ExitStatus> {
    Command::new("sh").arg("-c").arg(BOOTSTRAP).status()
}

pub fn cleanup() -> std::io::Result<std::process::ExitStatus> {
    Command::new("bash")
        .args(["-c", include_str!("../scripts/cleanup.sh")])
        .status()
}

pub fn count() -> std::io::Result<std::process::Output> {
    Command::new("sh").args(["-c", r#"ls /tmp | wc -l"#]).output()
}
