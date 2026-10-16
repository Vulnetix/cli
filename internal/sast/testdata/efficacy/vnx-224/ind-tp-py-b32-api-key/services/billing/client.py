import base64
from logging import getLogger

log = getLogger("billing")


class BillingClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.api_key = api_key
~>        log.debug("billing client ready url=%s key=%s", base_url, base64.b32encode(api_key.encode()))
