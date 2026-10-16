from flask import Flask

app = Flask(__name__)


@app.route("/ping")
def ping():
    return "pong"


@app.route("/ping")
def ping_again():
    return "pong"


def doc():
    """
    Example:
        @app.route("/ping")
        @app.route("/ping")
    """
    # @app.route("/ping")
    s = '@app.route("/ping")'
    return s
