import os
import tempfile


def write_pid():
    pid_path = os.path.join(tempfile.gettempdir(), "worker.pid")
~>    with open(pid_path, "w") as fh:
        fh.write(str(os.getpid()))


def share_socket():
~>    os.chmod("/tmp/worker.sock", 0o777)
