import tarfile


def restore(path, target):
    with tarfile.open(path) as tf:
~>        tf.extractall(target, members=tf.getmembers())
