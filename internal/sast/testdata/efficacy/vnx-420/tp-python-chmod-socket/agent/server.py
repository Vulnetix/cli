import os
import socket
import stat

SOCK = "/var/run/agent.sock"


def serve():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(SOCK)
~>    os.chmod(SOCK, 0o666)
~>    os.chmod(SOCK, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWOTH)
    s.listen(5)
