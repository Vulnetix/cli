import re

from flask import request, abort
from werkzeug.utils import secure_filename


def store_attachment():
    upload = request.files["attachment"]
    filename = secure_filename(upload.filename)
~>    if filename.rsplit(".", 1)[-1] in ["php", "exe", "jsp"]:
        abort(415)
~>    if re.search(r"\.(sh|cgi|pl)$", upload.filename):
        abort(415)
    upload.save("/data/" + filename)
