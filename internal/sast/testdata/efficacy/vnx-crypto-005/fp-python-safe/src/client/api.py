import ssl

import requests
import urllib3

CA_BUNDLE = "/etc/ssl/certs/internal-ca.pem"
HELP = "pass verify=False only when debugging locally"


def fetch(url):
    return requests.get(url, verify=True)


def fetch_internal(url):
    return requests.get(url, verify=CA_BUNDLE)


class Client:
    def __init__(self, verify=True):
        self.verify = verify

    def get(self, url):
        # requests.get(url, verify=False) used to be here
        return requests.get(url, verify=self.verify)


def strict_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED")
use_ssl = False
