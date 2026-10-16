import zipfile

from flask import Flask, abort, request

app = Flask(__name__)
MAX_UNPACKED = 200 * 1024 * 1024


@app.post("/imports")
def import_bundle():
    upload = request.files["bundle"]
    with zipfile.ZipFile(upload) as zf:
        total = sum(info.file_size for info in zf.infolist())
        if total > MAX_UNPACKED:
            abort(413)
        zf.extractall("/srv/imports/current")
    return {"ok": True}
