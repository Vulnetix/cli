import os


def collect(root):
    out = []
    for name in os.listdir(root):
        if name.endswith(".md"):
            out.append(name)
        base, ext = os.path.splitext(name)
        if ext == ".rst":
            out.append(base)
    return out
