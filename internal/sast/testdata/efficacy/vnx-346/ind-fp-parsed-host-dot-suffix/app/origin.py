import re
from urllib.parse import urlparse

from flask import request

ALLOWED = {"https://acme.com", "https://www.acme.com"}
ORIGIN_RE = re.compile(r"^https://([a-z0-9-]+\.)?acme\.com$")


def origin_ok():
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED:
        return True
    host = urlparse(origin).hostname or ""
    if host == "acme.com" or host.endswith(".acme.com"):
        return True
    if not origin.startswith("https://"):
        return False
    return re.fullmatch(r"https://[a-z]+\.acme\.com", origin) is not None or bool(ORIGIN_RE.match(origin))
