import os


def ext_of(f):
    a = os.path.splitext(f.filename)[1].lower()
    b = f.filename.rsplit(".", 1)[-1]
    c = f.filename.split(".")[-1]
    ok = f.filename.lower().endswith((".png", ".jpg"))
    return a, b, c, ok
