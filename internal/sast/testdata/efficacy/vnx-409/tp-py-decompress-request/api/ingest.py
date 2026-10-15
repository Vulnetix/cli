import gzip
import zlib as z

from flask import request


@app.route("/ingest", methods=["POST"])
def ingest():
    payload = request.get_data()
~>    raw = gzip.decompress(payload)
    return handle(raw)


@app.route("/ingest/deflate", methods=["POST"])
def ingest_deflate():
~>    body = z.decompress(request.data)
    return handle(body)


def django_view(request):
    blob = request.body
~>    text = lzma.decompress(blob).decode()
    return text
