import os


def upload(f):
    ext = f.filename.rsplit(".", 1)[1].lower()
    ext2 = os.path.splitext(f.filename)[1]
    ext3 = f.filename.split(".")[-1]
    if f.filename.lower().endswith((".png", ".jpg")):
        return ext + ext2 + ext3
    version = "1.2.3".split(".")[1]
    return version
