from flask import Flask

app = Flask(__name__)


@app.route("/admin/test-only")
def fake_admin():
    return "ok"
