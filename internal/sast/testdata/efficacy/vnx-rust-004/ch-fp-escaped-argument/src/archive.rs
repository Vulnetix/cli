use std::process::Command;

pub fn extract(name: &str) -> std::io::Result<std::process::ExitStatus> {
    let quoted = shlex::try_quote(name).expect("no nul bytes");
    Command::new("sh")
        .arg("-c")
        .arg(format!("tar -xzf {} -C /srv/data", quoted))
        .status()
}

pub fn remove(name: &str) -> std::io::Result<std::process::ExitStatus> {
    Command::new("bash")
        .arg("-c")
        .arg(format!("rm -f -- {}", shell_escape::escape(name.into())))
        .status()
}
