import os


def daemonize():
    if os.fork():
        os._exit(0)
    os.setsid()
    os.umask(0o027)
    os.chdir("/")
