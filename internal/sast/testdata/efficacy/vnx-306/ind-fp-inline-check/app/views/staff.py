from flask import Flask, abort
from flask_login import current_user

from app.reports import build_payroll_report

app = Flask(__name__)


@app.route("/staff/payroll/export")
def export_payroll():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)
    return build_payroll_report()
