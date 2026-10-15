import tarfile


def read_manifest(path):
    with tarfile.open(path) as tf:
        member = tf.getmember("manifest.json")
        return tf.extractfile(member).read()
