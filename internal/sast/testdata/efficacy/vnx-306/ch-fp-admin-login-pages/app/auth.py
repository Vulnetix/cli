from flask import Flask, render_template, redirect

app = Flask(__name__)


@app.route("/admin/login")
def admin_login_form():
    return render_template("admin/login.html")


@app.route("/admin/logout")
def admin_logout():
    return redirect("/")


@app.get("/admin/forgot-password")
def forgot():
    return render_template("admin/forgot.html")
