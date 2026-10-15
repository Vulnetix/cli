from flask import abort, request


def reject_ambiguous_framing():
    te = request.headers.get("Transfer-Encoding")
    cl = request.headers.get("Content-Length")
    if te is not None and cl is not None:
        abort(400)
