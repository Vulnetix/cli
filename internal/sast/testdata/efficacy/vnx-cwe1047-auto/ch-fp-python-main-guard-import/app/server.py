from flask import Flask


def create_app():
    app = Flask(__name__)
    return app


if __name__ == "__main__":
    from app.cli import run
    run()
