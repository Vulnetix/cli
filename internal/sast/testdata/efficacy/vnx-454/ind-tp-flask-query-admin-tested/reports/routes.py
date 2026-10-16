from flask import Blueprint, render_template, request

from .models import Report

bp = Blueprint("reports", __name__)


@bp.route("/reports")
def reports():
~>    if request.args.get("admin") == "1":
        rows = Report.query.all()
    else:
        rows = Report.query.filter_by(public=True).all()
    return render_template("reports.html", reports=rows)
