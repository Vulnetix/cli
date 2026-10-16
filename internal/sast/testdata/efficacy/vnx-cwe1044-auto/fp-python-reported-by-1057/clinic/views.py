from flask import Blueprint, jsonify

from clinic.db import get_db

bp = Blueprint("visits", __name__)


@bp.route("/visits/<int:patient_id>")
def visits(patient_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, seen_at FROM visit WHERE patient_id = ?", (patient_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])
