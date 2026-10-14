import os


def make_dirs(root):
    os.makedirs(os.path.join(root, "cache"), mode=0o777, exist_ok=True)
    os.mkdir(os.path.join(root, "spool"), 0o777)
    fd = os.open(os.path.join(root, "pid"), os.O_CREAT | os.O_WRONLY, 0o666)
    os.close(fd)
