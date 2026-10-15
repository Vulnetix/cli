import tarfile as tf


def unpack(path, dest):
    with tf.open(path, "r:gz") as arc:
~>        arc.extractall(dest)
