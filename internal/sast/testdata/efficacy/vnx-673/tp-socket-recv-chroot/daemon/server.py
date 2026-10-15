import os


def serve(conn):
    target = conn.recv(256).decode()
~>    os.chroot(target)
