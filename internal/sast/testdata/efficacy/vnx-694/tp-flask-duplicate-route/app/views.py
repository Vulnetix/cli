from flask import Flask, abort, session

app = Flask(__name__)


@app.route("/admin/users")
def list_users():
    return render_users()


~>@app.route("/admin/users")
def list_users_checked():
    if not session.get("is_admin"):
        abort(403)
    return render_users()
