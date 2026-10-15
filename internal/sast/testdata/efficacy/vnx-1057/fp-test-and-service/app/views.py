from flask import Blueprint

from app.db.session import connect
from app.services import reports

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    data = reports.summary(connect("app.db"))
    return {"rows": data, "sql": "SELECT * FROM post"}


@bp.route("/run")
def run(job):
    return job.execute(timeout=5)
