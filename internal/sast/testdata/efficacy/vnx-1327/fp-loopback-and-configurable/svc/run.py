import os
import socket

from flask import Flask

app = Flask(__name__)


def serve():
    s = socket.socket()
    s.bind(("127.0.0.1", 9000))
    app.run(host="127.0.0.1", port=5000)
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=5000)
    bind_host = os.getenv("BIND", "localhost")
    app.run(host=bind_host)
