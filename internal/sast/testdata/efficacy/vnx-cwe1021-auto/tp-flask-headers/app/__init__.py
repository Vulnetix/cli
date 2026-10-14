from flask import Flask, render_template
from flask_talisman import ALLOW_FROM, Talisman

app = Flask(__name__)
~>Talisman(app, frame_options=ALLOW_FROM, frame_options_allow_from="https://cms.example.net")


@app.after_request
def set_headers(response):
~>    response.headers["X-Frame-Options"] = "ALLOWALL"
~>    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors *"
    return response


@app.route("/widget")
def widget():
    resp = app.make_response(render_template("widget.html"))
~>    del resp.headers['X-Frame-Options']
    return resp
