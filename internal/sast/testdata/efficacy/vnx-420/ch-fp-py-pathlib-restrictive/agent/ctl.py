import socket
from pathlib import Path

SOCK = Path("/run/agent/ctl.sock")


def open_ctl():
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(SOCK))
    SOCK.chmod(0o600)
    Path("/run/agent").chmod(0o750)
    srv.listen(4)
    return srv
