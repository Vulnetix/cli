import requests


def build_session(settings, insecure: bool = False) -> requests.Session:
    s = requests.Session()
    s.verify = settings.CA_BUNDLE
    if insecure:
        s.verify = False
    return s


def get(settings, url):
    return requests.get(url, verify=settings.VERIFY_TLS, timeout=10)
