use std::process::Command;

pub fn restart(service: &str) {
    let _ = Command::new("sh").arg("-c").arg("sync");
~>    let _ = Command::new("sh").arg("-c").arg(format!("systemctl restart {}", service)).status();
    let _ = Command::new("logger").arg(service).status();
}
