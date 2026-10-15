import tarfile


def unpack(path, out):
    with tarfile.open(path) as tf:
        tf.extractall(out, filter=tarfile.tar_filter)
