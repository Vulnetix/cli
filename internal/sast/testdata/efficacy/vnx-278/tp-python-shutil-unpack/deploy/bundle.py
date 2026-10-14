import shutil


def install_bundle(bundle, target):
~>    shutil.unpack_archive(bundle, target)
