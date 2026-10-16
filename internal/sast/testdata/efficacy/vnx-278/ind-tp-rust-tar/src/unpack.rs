use std::fs::File;
use tar::Archive;

pub fn unpack(path: &str, dest: &str) -> std::io::Result<()> {
    let mut archive = Archive::new(File::open(path)?);
~>    archive.set_preserve_permissions(true);
~>    archive.set_preserve_ownerships(true);
    archive.unpack(dest)
}
