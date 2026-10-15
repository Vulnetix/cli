import os


def check(f, version):
    ext = os.path.splitext(f.filename)[1].lower()
    if not f.filename.lower().endswith((".png", ".jpg")):
        raise ValueError
    if not any(f.filename.lower().endswith(e) for e in ALLOWED):
        raise ValueError
    major = version.split(".")[1]
    stem = f.filename.rsplit(".", 1)[0]
    return ext, major, stem
