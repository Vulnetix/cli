import os


def make_tree(root):
    os.makedirs(os.path.join(root, "data"), 0o777, exist_ok=True)
    fd = os.open(os.path.join(root, "data", "db"), os.O_CREAT | os.O_WRONLY, 0o666)
    os.close(fd)
    os.chmod(os.path.join(root, "data"), 0o755)
