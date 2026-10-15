from flask import Flask

from app.models import User, db


def make_app():
    app = Flask(__name__)

    @app.route("/admin/reset", methods=["POST"])
    def reset():
        User.query.delete()
        db.session.commit()
        return ""

    return app
