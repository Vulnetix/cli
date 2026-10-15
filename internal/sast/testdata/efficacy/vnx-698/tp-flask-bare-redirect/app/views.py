from flask import Flask, redirect, session, url_for

app = Flask(__name__)


@app.route("/admin/purge", methods=["POST"])
def purge():
    if not session.get("is_admin"):
~>        redirect(url_for("login"))
    purge_all_records()
    return "done"
