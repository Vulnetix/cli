import shutil
import tarfile


def unpack(src, dst):
    shutil.unpack_archive(src, dst, filter="data")


def unpack_tar(src, dst):
    with tarfile.open(src) as tf:
        tf.extractall(dst, filter=tarfile.data_filter)
        tf.extract("README", dst, filter="tar")
