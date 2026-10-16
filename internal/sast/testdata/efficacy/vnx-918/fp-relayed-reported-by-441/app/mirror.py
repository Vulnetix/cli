import requests
from flask import Flask, Response, request

app = Flask(__name__)


# The fetched page is returned to the caller: an open proxy, reported by
# VNX-441. This rule leaves the line to it.
@app.route("/mirror")
def mirror():
    page = requests.get(request.args["page"], timeout=5)
    return Response(page.content, mimetype="text/html")
