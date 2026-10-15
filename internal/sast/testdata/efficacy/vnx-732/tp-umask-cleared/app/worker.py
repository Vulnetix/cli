import os


def daemonize():
    os.setsid()
~>    os.umask(0)
    os.chdir("/")


def make_spool(path):
~>    os.umask(0o000)
    os.makedirs(path, exist_ok=True)
