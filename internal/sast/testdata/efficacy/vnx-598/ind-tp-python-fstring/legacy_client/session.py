import requests


class LegacyPortal:
    def __init__(self, base, timeout=15):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def login(self, username, password):
~>        url = f"{self.base}/cgi-bin/login?user={username}&password={password}"
        resp = requests.get(url, timeout=self.timeout)
        resp.raise_for_status()
        return resp.cookies
