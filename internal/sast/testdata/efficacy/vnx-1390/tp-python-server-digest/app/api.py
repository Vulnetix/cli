from flask import Flask
from flask_httpauth import HTTPDigestAuth

app = Flask(__name__)
~>auth = HTTPDigestAuth()


@app.route("/admin")
@auth.login_required
def admin():
    return "ok"
