# Never send both "Content-Length": n and "Transfer-Encoding": "chunked".
WARNING = "A message with Transfer-Encoding: chunked must not carry Content-Length"


def framing(headers):
    return headers.get("Transfer-Encoding") or headers.get("Content-Length")
