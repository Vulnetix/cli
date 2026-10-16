use nix::unistd::{self, Uid};

pub fn enter(root: &str) -> nix::Result<()> {
~>    nix::unistd::chroot(root)?;
    unistd::setuid(Uid::from_raw(65534))?;
    Ok(())
}
