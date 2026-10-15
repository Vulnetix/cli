use std::fs::{self, DirBuilder, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub fn prepare(dir: &Path, file: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o777).create(dir)?;
    OpenOptions::new().create(true).write(true).mode(0o666).open(file)?;
    fs::set_permissions(file, fs::Permissions::from_mode(0o644))?;
    println!("never use from_mode(0o777)");
    Ok(())
}
