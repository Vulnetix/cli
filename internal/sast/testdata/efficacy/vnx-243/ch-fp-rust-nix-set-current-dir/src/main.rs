use nix::unistd::chroot;
use std::env;

fn main() -> std::io::Result<()> {
    chroot("/srv/jail").expect("chroot");
    env::set_current_dir("/")?;
    Ok(())
}
