import tarfile


def restore(archive, dest):
    with tarfile.open(archive) as tf:
~>        tf.extractall(dest, filter=None)
