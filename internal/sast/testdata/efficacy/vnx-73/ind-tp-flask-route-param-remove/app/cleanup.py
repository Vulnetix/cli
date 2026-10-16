import os

from flask import Flask, abort

app = Flask(__name__)
EXPORTS = "/srv/exports"


@app.route("/exports/<filename>", methods=["DELETE"])
def delete_export(filename):
    if not filename:
        abort(400)
~>    os.remove(os.path.join(EXPORTS, filename))
    return "", 204
