import os

UPLOAD_ROOT = "/srv/uploads"


def save_upload(filename, data):
    # TODO(alice): user filename can contain ../ and lead to path traversal
    dest = os.path.join(UPLOAD_ROOT, filename)
    with open(dest, "wb") as fh:
        fh.write(data)
    return dest
