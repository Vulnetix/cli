use std::fs::File;
use std::io;
use std::path::Path;

use tar::Archive;

pub fn unpack(src: &Path, dst: &Path) -> io::Result<()> {
    let mut archive = Archive::new(File::open(src)?);
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);
    archive.set_overwrite(true);
    // archive.set_preserve_permissions(true) would keep setuid bits
    archive.unpack(dst)
}
