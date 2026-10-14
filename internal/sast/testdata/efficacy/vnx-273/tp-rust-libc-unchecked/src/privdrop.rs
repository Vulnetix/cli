use libc::{gid_t, uid_t};

pub fn drop_to(uid: uid_t, gid: gid_t) {
    unsafe {
~>        libc::setgid(gid);
~>        libc::setuid(uid);
    }
    run_untrusted();
}

pub fn drop_euid(uid: uid_t) {
~>    unsafe { libc::seteuid(uid) };
    parse_input();
}
