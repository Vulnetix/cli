from flask import Blueprint, abort, jsonify, request

from app.services import reports

bp = Blueprint("reports", __name__)


@bp.route("/reports/<int:report_id>", methods=["DELETE"])
def delete_report(report_id):
~>    if request.args.get("role") != "admin":
        abort(403)
    reports.delete(report_id)
    return "", 204


@bp.route("/reports/export", methods=["POST"])
def export_all():
    privileges = request.json.get("privileges", [])
    fmt = request.json.get("format", "csv")
~>    if "export" not in privileges:
        abort(403)
    return jsonify(reports.export(fmt))
