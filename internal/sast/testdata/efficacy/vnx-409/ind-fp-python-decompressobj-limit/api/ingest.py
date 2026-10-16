import json
import zlib

from flask import Blueprint, abort, request

bp = Blueprint("ingest", __name__)
MAX_BODY = 8 * 1024 * 1024


@bp.post("/v1/events")
def ingest_events():
    payload = request.get_data()
    if request.headers.get("Content-Encoding") == "gzip":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        payload = d.decompress(payload, MAX_BODY)
        if d.unconsumed_tail:
            abort(413)
    return {"accepted": len(json.loads(payload))}, 202
