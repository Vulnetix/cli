import os

from flask import Blueprint, request, send_file
from werkzeug.utils import secure_filename

BASE = "/srv/app/templates"
bp = Blueprint("files", __name__)


@bp.route("/template")
def get_template():
    name = os.path.basename(request.args["name"])
    with open(os.path.join(BASE, name)) as fh:
        return fh.read()


@bp.route("/invoice")
def invoice():
    num = int(request.args["n"])
    return send_file(os.path.join("/srv/invoices", "%d.pdf" % num))


@bp.route("/avatar")
def avatar():
    fname = secure_filename(request.args.get("f", ""))
    return send_file(os.path.join("/srv/avatars", fname))
