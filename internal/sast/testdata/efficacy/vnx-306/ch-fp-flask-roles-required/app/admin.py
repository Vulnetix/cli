from flask import Flask
from flask_security import roles_required

app = Flask(__name__)


@app.route("/admin/dashboard")
@roles_required("admin")
def dashboard():
    return "ok"
