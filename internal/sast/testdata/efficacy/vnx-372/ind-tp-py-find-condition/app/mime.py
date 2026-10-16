def is_json(content_type: str) -> bool:
~>    if content_type.find("application/json"):
        return True
    return False


def wants_gzip(headers: dict) -> bool:
    accept = headers.get("Accept-Encoding", "")
~>    return bool(accept.find("gzip"))
