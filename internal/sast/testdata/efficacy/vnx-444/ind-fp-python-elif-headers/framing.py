def build_headers(body, stream=None):
    headers = {"Content-Type": "application/octet-stream"}
    if body is not None:
        headers["Content-Length"] = str(len(body))
    elif stream is not None:
        headers["Transfer-Encoding"] = "chunked"
    return headers
