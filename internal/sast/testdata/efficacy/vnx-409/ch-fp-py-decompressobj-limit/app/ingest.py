import zlib

from flask import Flask, abort, request

app = Flask(__name__)
LIMIT = 10 * 1024 * 1024


@app.post("/ingest")
def ingest():
    d = zlib.decompressobj()
    body = d.decompress(request.data, LIMIT)
    if d.unconsumed_tail:
        abort(413)
    return {"n": len(body)}
