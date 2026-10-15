from flask import request, abort, jsonify
from flask_login import current_user


def export_report():
    if request.headers.get("Accept") == "text/csv":
        fmt = "csv"
    else:
        fmt = "json"
    if current_user.role == "admin":
        return render(load_all_reports(), fmt)
    abort(403)
