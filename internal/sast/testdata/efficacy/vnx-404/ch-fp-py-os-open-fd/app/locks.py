import os
import webbrowser


def take_lock(path):
    fd = os.open(path, os.O_CREAT | os.O_RDWR)
    os.lockf(fd, os.F_LOCK, 0)
    return fd


def show(url):
    ok = webbrowser.open(url)
    print(ok)
