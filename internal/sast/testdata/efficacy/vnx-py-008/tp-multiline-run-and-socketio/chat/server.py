import flask
from flask_socketio import SocketIO

application = flask.Flask(__name__)
socketio = SocketIO(application)


def main():
~>    application.run(
        host="0.0.0.0",
        debug = True,
    )


def main_ws():
~>    socketio.run(application, port=8000, debug=True)
