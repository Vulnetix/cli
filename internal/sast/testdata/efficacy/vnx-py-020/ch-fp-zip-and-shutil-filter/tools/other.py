import shutil
import zipfile


def unpack(path, out):
    with zipfile.ZipFile(path) as zf:
        zf.extractall(out)
    shutil.unpack_archive(path, out, filter="data")
