import requests


class VaultClient:
~>    def __init__(self, base_url, token, insecure=True):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = not insecure
        self.session.headers["X-Vault-Token"] = token
