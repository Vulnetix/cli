from flask import Flask, jsonify

from app.models import User, db

app = Flask(__name__)


~>@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"deleted": user_id})
