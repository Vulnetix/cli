use std::process::Command;

pub fn uptime() {
    let _ = Command::new("sh").arg("-c").arg("uptime && date").output();
    let _ = Command::new("bash")
        .arg("-c")
        .arg("echo (starting) > /tmp/marker")
        .status();
    let _ = Command::new("sh").args(["-c", "ls -la /var/log"]).output();
}
