from flask import Flask, render_template

from .db import query

app = Flask(__name__)


@app.route("/profile/<int:profile_id>")
def show_profile(profile_id):
~>    row = query(f"SELECT name, email, phone FROM profiles WHERE profile_id = {profile_id}")
    return render_template("profile.html", row=row)
