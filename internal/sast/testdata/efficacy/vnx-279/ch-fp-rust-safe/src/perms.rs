use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn prepare(bin: &Path) -> io::Result<()> {
    fs::set_permissions(bin, fs::Permissions::from_mode(0o755))?;
    let mode = fs::metadata(bin)?.permissions().mode();
    if mode & 0o4000 != 0 {
        fs::set_permissions(bin, fs::Permissions::from_mode(mode & !0o4000))?;
    }
    Ok(())
}
