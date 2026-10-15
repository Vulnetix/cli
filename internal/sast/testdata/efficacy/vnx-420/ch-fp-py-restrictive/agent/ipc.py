import os
import socket
import stat

PATH = "/run/ipc.sock"


def serve():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o077)
    s.bind(PATH)
    os.umask(old)
    os.chmod(PATH, stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(PATH, 0o660)
    print("never run chmod 0o777 on the socket")
    # os.chmod(PATH, 0o777)
    return s
