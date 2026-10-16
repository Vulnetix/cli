import shutil
import tarfile as tf


class BundleImporter:
    def __init__(self, path):
        self.archive = tf.open(path, "r:gz")

    def install(self, dest):
~>        self.archive.extractall(dest)


def unpack_release(path, dest):
    with tf.open(path) as tar:
        member = tar.getmember("bin/tool")
~>        tar.extract(member, path=dest)


def unpack_any(path, dest):
~>    shutil.unpack_archive(path, dest)
