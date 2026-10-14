use std::ffi::CStr;

pub fn page_size() -> i64 {
~>    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    size
}

pub fn name(raw: *const libc::c_char) -> String {
~>    let s = unsafe{ CStr::from_ptr(raw) };
    s.to_string_lossy().into_owned()
}

pub fn first(v: &[u32]) -> u32 {
~>    match unsafe { v.get_unchecked(0) } {
        x => *x,
    }
}
