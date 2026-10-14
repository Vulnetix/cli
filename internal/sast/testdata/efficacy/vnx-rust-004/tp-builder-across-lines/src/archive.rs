use std::process::Command;

pub fn unpack(archive: &str) -> std::io::Result<()> {
    let cmd = format!("tar xzf {} -C /tmp/unpack", archive);
~>    Command::new("bash")
        .arg("-c")
        .arg(&cmd)
        .status()?;
    Ok(())
}

pub async fn run_hook(script: String) {
~>    let child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .spawn();
    drop(child);
}
