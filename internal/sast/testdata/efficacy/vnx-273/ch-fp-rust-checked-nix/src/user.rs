use nix::unistd::{setgid, setuid, Gid, Uid};

pub fn drop_to(uid: u32, gid: u32) -> nix::Result<()> {
    setgid(Gid::from_raw(gid))?;
    setuid(Uid::from_raw(uid)).expect("setuid");
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(nix::Error::last());
    }
    let rc = unsafe { libc::setuid(uid) };
    assert_eq!(rc, 0);
    Ok(())
}
