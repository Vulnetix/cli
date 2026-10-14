import os
import sys


def daemonize():
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
~>    os.umask(0)
    os.chdir("/")


def prepare_spool(path):
~>    os.umask(0o000)
    os.makedirs(path, exist_ok=True)
