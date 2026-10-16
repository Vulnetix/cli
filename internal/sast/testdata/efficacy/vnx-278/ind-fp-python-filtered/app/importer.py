import shutil
import tarfile
import zipfile


def install(path, dest):
    with tarfile.open(path) as tar:
        tar.extractall(dest, filter="data")


def install_zip(path, dest):
    with zipfile.ZipFile(path) as zf:
        zf.extractall(dest)


def unpack_wheel(path, dest):
    shutil.unpack_archive(path, dest, format="zip")


def unpack_tar(path, dest):
    shutil.unpack_archive(path, dest, filter="data")
