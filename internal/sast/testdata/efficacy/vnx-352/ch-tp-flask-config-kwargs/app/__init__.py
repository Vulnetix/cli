from flask import Flask
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=load_secret(),
~>        WTF_CSRF_ENABLED=False,
    )
    csrf.init_app(app)
    return app


def create_admin_app():
    admin = Flask("admin")
~>    admin.config.from_mapping(SECRET_KEY=load_secret(), WTF_CSRF_ENABLED=False)
    return admin
