import io
import tarfile


def import_bundle(data: bytes, dest: str):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as bundle:
~>        bundle.extractall(dest)
