import gzip
import json

from flask import Flask, request

app = Flask(__name__)


@app.post("/ingest")
def ingest():
    if request.headers.get("Content-Encoding") == "gzip":
~>        body = gzip.decompress(request.data)
    else:
        body = request.data
    return {"n": len(json.loads(body))}
