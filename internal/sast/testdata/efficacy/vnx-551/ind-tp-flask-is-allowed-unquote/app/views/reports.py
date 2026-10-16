from urllib.parse import unquote

from flask import Blueprint, abort, g, request, send_from_directory

from app.authz import is_allowed

bp = Blueprint("reports", __name__)
REPORT_DIR = "/var/lib/reports"


@bp.route("/reports/fetch")
def fetch_report():
    report = request.args.get("report", "")
~>    if not is_allowed(g.user, report):
        abort(403)

    decoded = unquote(report)
    return send_from_directory(REPORT_DIR, decoded)
