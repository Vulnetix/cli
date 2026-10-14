import tarfile as tf
from tarfile import TarFile


def fetch(path, cache):
    t = tf.open(path)
~>    t.extractall(
        path=cache,
    )


def fetch_plain(path, cache):
    with TarFile(path) as archive:
~>        archive.extractall(cache)
