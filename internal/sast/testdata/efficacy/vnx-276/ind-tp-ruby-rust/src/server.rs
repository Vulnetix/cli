use std::fs;
use std::os::unix::fs::PermissionsExt;

pub fn open_socket(sock: &str) -> std::io::Result<()> {
~>    fs::set_permissions(sock, fs::Permissions::from_mode(0o777))?;
    Ok(())
}
