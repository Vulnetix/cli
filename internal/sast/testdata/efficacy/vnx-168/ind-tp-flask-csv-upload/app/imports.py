from flask import Blueprint, request, jsonify

from .models import db, User

bp = Blueprint("imports", __name__)


@bp.route("/admin/users/import", methods=["POST"])
def import_users():
    csv_file = request.files["csv_file"]
    text = csv_file.read().decode("utf-8")
    created = 0
    for line in text.splitlines()[1:]:
        if not line.strip():
            continue
~>        name, email, role = line.strip().split(",")
        db.session.add(User(name=name, email=email, role=role))
        created += 1
    db.session.commit()
    return jsonify(created=created)
