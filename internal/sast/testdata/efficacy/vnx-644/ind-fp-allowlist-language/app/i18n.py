from flask import Flask, request, make_response

app = Flask(__name__)
SUPPORTED = {"en", "fr", "de"}


@app.route("/")
def index():
    resp = make_response(render_home())
    resp.headers["Content-Language"] = "en"
    resp.headers["Vary"] = "Accept-Language"
    return resp
