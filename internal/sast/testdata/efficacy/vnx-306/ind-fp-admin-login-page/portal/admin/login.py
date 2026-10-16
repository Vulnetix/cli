from flask import Flask, render_template

app = Flask(__name__)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    return render_template("admin/login.html")


@app.get("/admin/health")
def admin_health():
    return {"status": "ok"}
