import re
from urllib.parse import urlsplit

ORIGIN_RE = re.compile(r"^https://([a-z0-9-]+\.)?example\.com$")


def allowed(request):
    origin = request.headers.get("Origin", "")
    if not origin.startswith("https://"):
        return False
    if re.fullmatch(r"https://[a-z0-9-]+\.example\.com", origin):
        return True
    host = urlsplit(origin).hostname or ""
    return host == "example.com" or host.endswith(".example.com")
