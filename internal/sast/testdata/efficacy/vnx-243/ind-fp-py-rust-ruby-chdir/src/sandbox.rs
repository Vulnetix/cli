use std::os::unix::fs;

pub fn enter(root: &str) -> std::io::Result<()> {
    fs::chroot(root)?;
    std::env::set_current_dir("/")?;
    Ok(())
}
