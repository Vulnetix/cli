from urllib.parse import unquote

ALLOWED = {"/health", "/ready"}


def route(request):
    path = request.path
    if path == "/health":
        return "ok"
    query = unquote(request.query_string.decode())
    return query


def local_only(value):
    if value.startswith("/tmp"):
        return False
    return unquote(value)
