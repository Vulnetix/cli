import zlib

import requests


def fetch_snapshot(url):
    resp = requests.get(url, timeout=30)
~>    return zlib.decompress(resp.content)
