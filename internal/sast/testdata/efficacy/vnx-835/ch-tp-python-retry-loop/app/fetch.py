import time

import requests

MAX_ATTEMPTS = 5


def fetch_report(url):
    attempt = 0
    ok = False
~>    while attempt < MAX_ATTEMPTS:
        resp = requests.get(url, timeout=10)
        if resp.ok:
            ok = True
        time.sleep(1)
    return ok
