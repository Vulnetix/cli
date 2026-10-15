from flask import request, abort, jsonify


def export_report():
~>    if request.headers.get("X-User-Role") == "admin":
        return jsonify(load_all_reports())
    abort(403)
