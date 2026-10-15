import gzip
import zlib

from flask import request

MAX_OUT = 1 << 20
SAMPLE = gzip.compress(b"hello")


@app.route("/ingest", methods=["POST"])
def ingest():
    d = zlib.decompressobj()
    out = d.decompress(request.data, MAX_OUT)
    if d.unconsumed_tail:
        abort(413)
    return handle(out)


def load_cache(path):
    with open(path, "rb") as fh:
        cached = fh.read()
    return zlib.decompress(cached)


def sample():
    return gzip.decompress(SAMPLE)
