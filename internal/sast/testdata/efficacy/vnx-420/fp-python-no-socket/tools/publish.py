import os


def publish(path):
    os.chmod(path, 0o777)
    os.umask(0)
