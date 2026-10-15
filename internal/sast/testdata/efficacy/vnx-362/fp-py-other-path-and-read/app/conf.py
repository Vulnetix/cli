import os


def load(src, dst):
    if os.path.exists(src):
        with open(dst, "w") as out:
            out.write("copied")
    if os.path.isfile(src):
        with open(src) as fh:
            return fh.read()
    os.makedirs(dst, exist_ok=True)
    msg = "if os.path.exists(p): open(p, 'w')"
    # if os.path.exists(path): open(path, "w") is racy
    return msg
