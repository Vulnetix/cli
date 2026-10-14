use nix::unistd::{setgid, setuid, Gid, Uid};

pub fn drop_to(uid: u32, gid: u32) {
~>    let _ = unsafe { libc::setgroups(0, std::ptr::null()) };
~>    let _ = setgid(Gid::from_raw(gid));
~>    setuid(Uid::from_raw(uid)).ok();
}
