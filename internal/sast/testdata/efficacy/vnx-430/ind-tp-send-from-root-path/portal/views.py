from flask import Blueprint, current_app, send_from_directory

bp = Blueprint("files", __name__)


@bp.route("/download/<path:name>")
def download(name):
~>    return send_from_directory(current_app.root_path, name, as_attachment=True)
