import hashlib
import os


def store_upload(fileobj, dest_dir):
    """Persist an uploaded artefact and return its checksum for later integrity checks."""
~>    digest = hashlib.md5()
    dest = os.path.join(dest_dir, os.path.basename(fileobj.name))
    with open(dest, "wb") as out:
        for chunk in iter(lambda: fileobj.read(65536), b""):
            digest.update(chunk)
            out.write(chunk)
    return dest, digest.hexdigest()
