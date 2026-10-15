import tarfile

from flask import Flask, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_bundle():
    upload = request.files["bundle"]
    with tarfile.open(fileobj=upload.stream, mode="r:gz") as tar:
~>        tar.extractall("/srv/imports")
    return "", 204
