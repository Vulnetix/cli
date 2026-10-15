from flask import Flask, jsonify

from .models import User

app = Flask(__name__)


~>@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    return jsonify(ok=True)


@app.route("/health")
def health():
    return "ok"
