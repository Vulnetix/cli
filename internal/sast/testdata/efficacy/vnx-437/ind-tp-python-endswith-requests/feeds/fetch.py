import requests
from flask import abort, request


def import_feed():
    url = request.form["feed_url"]
    if not url.endswith(".newsdesk.com"):
        abort(400)
~>    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return parse_feed(resp.text)
