import os

from flask import Flask
from flask_wtf import CSRFProtect

csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]
~>    app.config["WTF_CSRF_ENABLED"] = False
    csrf.init_app(app)

    from .orders import bp as orders_bp
    app.register_blueprint(orders_bp)
    return app
