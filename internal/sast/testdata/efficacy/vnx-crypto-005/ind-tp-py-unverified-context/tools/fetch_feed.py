import json
import ssl
import urllib.request

FEED_URL = "https://feeds.example.internal/v1/prices.json"


def fetch():
~>    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(FEED_URL, context=ctx, timeout=10) as resp:
        return json.load(resp)
