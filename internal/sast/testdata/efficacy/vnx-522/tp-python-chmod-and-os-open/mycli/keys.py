import os


def write_private_key(pem, key_path):
~>    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT, 0o644)
    os.write(fd, pem)
    os.close(fd)


def relax(netrc_path):
~>    os.chmod(netrc_path, 0o644)
