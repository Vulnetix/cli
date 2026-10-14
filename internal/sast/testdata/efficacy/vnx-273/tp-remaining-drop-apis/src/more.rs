pub fn drop_groups(user: *const libc::c_char, gid: libc::gid_t) {
    unsafe {
~>        libc::initgroups(user, gid);
~>        libc::setgroups(0, std::ptr::null());
    }
}
