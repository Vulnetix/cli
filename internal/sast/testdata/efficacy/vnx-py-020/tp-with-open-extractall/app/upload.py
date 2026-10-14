import os
import tarfile


def unpack_upload(upload_path, dest):
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(upload_path, "r:gz") as tar:
~>        tar.extractall(dest)
    return dest


def unpack_both(a, b, out):
    with tarfile.open(os.path.join(out, a)) as src, open(b, "rb") as other:
~>        src.extractall(path=out)
        other.read()
