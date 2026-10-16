import gzip
import json

from flask import Blueprint, request

bp = Blueprint("ingest", __name__)


@bp.post("/v1/events")
def ingest_events():
    payload = request.get_data()
    if request.headers.get("Content-Encoding") == "gzip":
~>        payload = gzip.decompress(payload)
    events = json.loads(payload)
    return {"accepted": len(events)}, 202
