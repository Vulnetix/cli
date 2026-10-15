from flask import Blueprint

from app.queries import run_report

bp = Blueprint("reports", __name__)

REPORT_TITLE = "SELECT the best sellers"


@bp.get("/reports/top")
def top():
    sql_name = "top_sellers"
    return run_report(sql_name, title=REPORT_TITLE)
