use std::io;

pub fn drop_to(uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::setuid(uid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    nix::unistd::setuid(nix::unistd::Uid::from_raw(uid))?;
    Ok(())
}
