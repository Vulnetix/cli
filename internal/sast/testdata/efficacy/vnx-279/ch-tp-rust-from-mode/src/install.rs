use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn install_helper(helper: &Path) -> io::Result<()> {
~>    fs::set_permissions(helper, fs::Permissions::from_mode(0o4755))
}
