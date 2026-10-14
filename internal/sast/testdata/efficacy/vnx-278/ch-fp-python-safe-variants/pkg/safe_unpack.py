import json
import shutil
import tarfile
import zipfile


def _strip_modes(member, path):
    return member.replace(mode=0o644)


def unpack(archive, dest):
    with tarfile.open(archive) as tf:
        tf.extractall(dest, filter="data")
    with tarfile.open(archive) as tf:
        tf.extractall(
            dest,
            filter=tarfile.data_filter,
        )
    with tarfile.open(archive) as tf:
        tf.extractall(dest, filter=_strip_modes)
    with tarfile.open(archive) as tf:
        manifest = json.load(tf.extractfile("manifest.json"))
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest)
    shutil.unpack_archive(archive, dest, filter="data")
    return manifest
