import os

import requests

~>os.environ.update(REQUESTS_CA_BUNDLE="")
~>os.putenv("PYTHONHTTPSVERIFY", "0")
~>os.environ['GIT_SSL_NO_VERIFY'] = 'true'


def fetch(url):
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text
