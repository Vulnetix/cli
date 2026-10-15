import zipfile

from flask import request


def import_bundle(dest):
    upload = request.files["bundle"]
    with zipfile.ZipFile(upload) as archive:
        for name in archive.namelist():
~>            archive.extract(name, dest)
