import tarfile as tf


def unpack(path, dest):
    with tf.open(path, "r:gz") as arc:
        arc.extractall(dest, filter="data")


def install(bundle: tf.TarFile, dest):
    bundle.extractall(dest, filter=tf.data_filter)
