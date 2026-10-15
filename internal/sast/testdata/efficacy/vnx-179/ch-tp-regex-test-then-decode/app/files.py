import os
import re
from urllib.parse import unquote_plus

from flask import abort, request, send_file


def download():
    name = request.args.get("f", "")
~>    if re.search(r"\.\.", name):
        abort(400)
    name = unquote_plus(name)
    return send_file(os.path.join("/srv/files", name))
