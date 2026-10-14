import shutil
import tarfile
import zipfile


def unpack_release(path, dest):
    with tarfile.open(path) as tar:
        tar.extractall(dest, filter="data")


def unpack_tar_filter(path, dest):
    with tarfile.open(path) as tar:
        tar.extractall(dest, filter='tar')


def unpack_member(path, member, dest):
    tf = tarfile.open(path)
    tf.extract(member, dest, filter=tarfile.data_filter)


def unpack_zip(path, dest):
    zipfile.ZipFile(path).extractall(dest)
    with zipfile.ZipFile(path) as zf:
        zf.extractall(dest)


def unpack_bundle(bundle, target):
    shutil.unpack_archive(bundle, target, format="zip")
    shutil.unpack_archive(bundle, target, filter="data")
    # tar.extractall(dest) used to be here
