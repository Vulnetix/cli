use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn expose(sock: &Path, log_dir: &Path) -> io::Result<()> {
~>    fs::set_permissions(sock, fs::Permissions::from_mode(0o777))?;
    let mut perms = fs::metadata(log_dir)?.permissions();
~>    perms.set_mode(0o666);
    fs::set_permissions(log_dir, perms)
}
