import zipfile
from zipfile import ZipFile

from flask import request


@app.route("/import", methods=["POST"])
def import_bundle():
    upload = request.files["bundle"]
    with zipfile.ZipFile(upload) as zf:
~>        zf.extractall(UPLOAD_DIR)
    return "ok"


def unpack_theme(path, dest):
    archive = ZipFile(path, "r")
~>    archive.extractall(path=dest)
    archive.close()


def unpack_inline(path, dest):
~>    ZipFile(path).extractall(dest)
