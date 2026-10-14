import tarfile


def load(archive, plugin_dir):
    tf = tarfile.open(archive)
    for member in tf.getmembers():
        if member.name.endswith(".py"):
~>            tf.extract(member, plugin_dir)
    tf.close()
