import os


def handle_upload(f):
    ext = os.path.splitext(f.filename)[1].casefold()
    if ext == ".php":
        raise ValueError("blocked")
    return ext
