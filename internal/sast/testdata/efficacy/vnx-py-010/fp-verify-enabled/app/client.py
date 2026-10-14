import certifi
import requests

from app import settings

session = requests.Session()
session.verify = "/etc/ssl/certs/internal-ca.pem"


def fetch(url):
    a = requests.get(url, verify=True, timeout=10)
    b = requests.get(url, verify="/etc/ssl/certs/internal-ca.pem")
    c = requests.get(url, verify=settings.VERIFY_TLS)
    d = session.post(url, verify=certifi.where())
    return a, b, c, d
