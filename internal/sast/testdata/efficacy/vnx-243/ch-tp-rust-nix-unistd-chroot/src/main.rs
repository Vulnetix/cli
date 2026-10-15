use nix::unistd;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
~>    unistd::chroot("/srv/jail")?;
    Command::new("/bin/app").status()?;
    Ok(())
}
