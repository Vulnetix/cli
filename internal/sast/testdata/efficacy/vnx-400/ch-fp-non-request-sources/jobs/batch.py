import os
import time

import requests

RETRIES = int(os.environ.get("RETRIES", "3"))


def poll(url):
    for attempt in range(RETRIES):
        resp = requests.get(url, timeout=5)
        if resp.ok:
            return resp.json()
        time.sleep(2 ** attempt)
    return None


def chunked(resp):
    size = int(resp.headers.get("chunk", 1024))
    return resp.raw.read(min(size, 65536))
