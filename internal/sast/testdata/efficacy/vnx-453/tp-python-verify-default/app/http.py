import requests


~>def fetch_invoice(url, timeout=10, verify=False):
    return requests.get(url, timeout=timeout, verify=verify)


~>async def open_feed(host: str, port: int = 443, verify_ssl: bool = False):
    ...


class Uploader:
~>    def __init__(self, endpoint, check_hostname=False, insecure_skip_verify=True):
        self.endpoint = endpoint
