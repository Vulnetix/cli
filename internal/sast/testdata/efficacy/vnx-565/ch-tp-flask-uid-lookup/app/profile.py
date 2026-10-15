from flask import Flask, request, render_template

app = Flask(__name__)


@app.route("/profile")
def profile():
~>    uid = request.cookies.get("user_id")
    user = User.query.get(uid)
    return render_template("profile.html", user=user)
