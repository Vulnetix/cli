import tarfile


def restore(path, root):
    with tarfile.open(path) as archive:
~>        archive.extractall(root, filter="fully_trusted")


def restore_all(path, root):
    with tarfile.open(path) as archive:
~>        archive.extractall(root, members=archive.getmembers())
