from flask import Flask, render_template
from flask_login import login_required

from app.models import User

app = Flask(__name__)


@app.route("/admin/users")
@login_required
def list_users():
    return render_template("admin/users.html", users=User.query.all())
