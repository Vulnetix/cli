use daemonize::Daemonize;

fn create_private_socket() {
    let old = unsafe { libc::umask(0) };
    bind_socket();
    unsafe { libc::umask(old) };
}

fn main() {
    unsafe { libc::umask(0o077) };
    let daemon = Daemonize::new().umask(0o027).working_directory("/");
    daemon.start().expect("daemonize");
    create_private_socket();
}
