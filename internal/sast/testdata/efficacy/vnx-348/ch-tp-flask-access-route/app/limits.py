from flask import Flask, request

app = Flask(__name__)


def client_ip():
~>    return request.access_route[0] if request.access_route else request.remote_addr


@app.before_request
def throttle():
    key = client_ip()
    app.limiter.hit(key)
