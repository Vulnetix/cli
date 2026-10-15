import os


def open_socket_file(name):
~>    os.umask(0)
    fd = os.open(name, os.O_CREAT | os.O_WRONLY)
~>    os.fchmod(fd, 0o646)
    return fd
