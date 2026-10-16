use nix::unistd::{setgid, setuid, Gid, Uid};

pub fn drop_to(uid: u32, gid: u32) -> nix::Result<()> {
    setgid(Gid::from_raw(gid))?;
    setuid(Uid::from_raw(uid)).expect("setuid failed");
    Ok(())
}
