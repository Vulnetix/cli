from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app)


@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    return authenticate(request.form["user"], request.form["pw"])
