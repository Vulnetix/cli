from flask import Blueprint, Flask, render_template, request

from .models import User, db

app = Flask(__name__)
admin_bp = Blueprint("admin", __name__)


~>@app.route("/admin/users")
def list_users():
    users = User.query.all()
    return render_template("admin/users.html", users=users)


~>@admin_bp.route('/administration/delete/<int:uid>', methods=["POST"])
def delete_user(uid):
    db.session.delete(User.query.get(uid))
    db.session.commit()
    return "", 204


~>@app.route("/staff/report")
~>@app.route("/backoffice/report")
def report():
    return render_template("report.html")


~>@app.get(
    "/manage/settings"
)
def settings():
    return {"debug": app.debug}
