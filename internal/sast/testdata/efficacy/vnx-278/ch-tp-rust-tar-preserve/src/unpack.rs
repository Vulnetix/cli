use std::fs::File;
use std::io;
use std::path::Path;

use flate2::read::GzDecoder;
use tar::Archive;

pub fn unpack(src: &Path, dst: &Path) -> io::Result<()> {
    let mut archive = Archive::new(GzDecoder::new(File::open(src)?));
~>    archive.set_preserve_permissions(true);
~>    archive.set_preserve_ownerships(true);
    archive.unpack(dst)
}
