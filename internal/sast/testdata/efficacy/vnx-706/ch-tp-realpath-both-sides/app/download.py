import os

from flask import abort, request, send_file

DOWNLOADS = "/srv/downloads"


def download():
    requested = os.path.join(DOWNLOADS, request.args["f"])
~>    if not os.path.realpath(requested).startswith(os.path.realpath(DOWNLOADS)):
        abort(403)
    return send_file(requested)
