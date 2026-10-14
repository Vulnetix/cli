import io
import tarfile


def unpack_release(path, dest):
    with tarfile.open(path) as tar:
~>        tar.extractall(dest)


def unpack_member(blob, member, dest):
    tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
~>    tf.extract(member, dest)


def unpack_inline(path, dest):
~>    tarfile.open(path).extractall(dest)


def unpack_trusted(path, dest):
    with tarfile.open(path, "r:*") as archive:
~>        archive.extractall(dest, filter="fully_trusted")


def unpack_selected(path, dest, wanted):
    with tarfile.open(path) as tar:
~>        tar.extractall(
            path=dest,
            members=[m for m in tar.getmembers() if m.name in wanted],
        )
