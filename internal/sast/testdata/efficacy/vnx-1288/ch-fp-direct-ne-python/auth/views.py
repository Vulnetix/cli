from flask import Blueprint, request, abort

bp = Blueprint("auth", __name__)


@bp.route("/register", methods=["POST"])
def register():
    if request.form["password"] != request.form["password_confirm"]:
        abort(400, "passwords do not match")
    data = request.get_json()
    again = request.json.get("passwordAgain")
    if again != data.get("password"):
        abort(400)
    return "ok"
