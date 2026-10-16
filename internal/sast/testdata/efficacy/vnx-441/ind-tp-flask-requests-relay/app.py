from flask import Flask, Response, request
import requests

app = Flask(__name__)


@app.route("/preview")
def preview():
    target = request.args.get("url", "")
    if not target:
        return {"error": "url required"}, 400
~>    upstream = requests.get(target, timeout=10, allow_redirects=True)
    return Response(
        upstream.content,
        status=upstream.status_code,
        content_type=upstream.headers.get("Content-Type", "text/html"),
    )
