import zipfile

from flask import request

LIMIT = 50 * 1024 * 1024


def import_bundle(dest):
    upload = request.files["bundle"]
    with zipfile.ZipFile(upload) as archive:
        total = 0
        for info in archive.infolist():
            total += info.file_size
            if total > LIMIT:
                raise ValueError("archive too large")
            archive.extract(info, dest)
