import requests


def fetch(url, ca_bundle):
    a = requests.get(url, verify=True)
    b = requests.get(url, verify="/etc/ssl/certs/internal-ca.pem")
    c = requests.post(url, json={}, verify=ca_bundle)
    s = requests.Session()
    s.verify = "/etc/ssl/certs/ca-certificates.crt"
    return a, b, c
