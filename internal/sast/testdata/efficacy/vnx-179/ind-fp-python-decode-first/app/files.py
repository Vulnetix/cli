import os
from urllib.parse import unquote

from flask import abort, request, send_file


@app.route("/download")
def download():
    name = unquote(request.args.get("name", ""))
    if ".." in name or name.startswith("/"):
        abort(400)
    return send_file(os.path.join("/srv/files", name))
