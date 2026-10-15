use daemonize::Daemonize;

fn detach() {
    unsafe {
~>        libc::umask(0);
    }
}

fn main() {
    let daemon = Daemonize::new()
        .pid_file("/run/agent.pid")
~>        .umask(0o000)
        .working_directory("/");
    daemon.start().expect("daemonize");
    detach();
}
