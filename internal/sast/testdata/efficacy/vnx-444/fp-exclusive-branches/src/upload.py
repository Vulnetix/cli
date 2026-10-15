def prepare_body(headers, body, length):
    if length:
        headers["Content-Length"] = str(length)
    else:
        headers["Transfer-Encoding"] = "chunked"
    return headers
