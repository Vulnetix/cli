use std::os::unix::fs;

pub fn enter(dir: &str) -> std::io::Result<()> {
~>    fs::chroot(dir)?;
    drop_privileges();
    Ok(())
}
