import os
import pwd
import socket


def serve(port):
    sock = socket.socket()
    sock.bind(("0.0.0.0", port))
    nobody = pwd.getpwnam("nobody")
    os.setgid(nobody.pw_gid)
~>    os.setuid(nobody.pw_uid)
    sock.listen()
    return sock
