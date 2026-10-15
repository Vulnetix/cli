from flask import Flask, request, Response
import requests

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    target = request.args.get("url")
~>    upstream = requests.get(target, timeout=5)
    return Response(upstream.content, status=upstream.status_code,
                    content_type=upstream.headers.get("Content-Type"))


@app.route("/preview", methods=["POST"])
def preview():
~>    r = requests.get(request.form["link"])
    return r.text
