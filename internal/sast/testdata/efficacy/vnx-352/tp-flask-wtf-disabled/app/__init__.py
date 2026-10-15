from flask import Flask
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)
~>    app.config["WTF_CSRF_ENABLED"] = False
    csrf.init_app(app)
    return app


~>@csrf.exempt
@app_route("/transfer", methods=["POST"])
def transfer():
    return "ok"
