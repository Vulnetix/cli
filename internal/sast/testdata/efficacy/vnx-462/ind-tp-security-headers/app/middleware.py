DEFAULT_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
~>    "X-Frame-Options": "SAMEORIGIN",
}


def apply_headers(response):
    for name, value in DEFAULT_HEADERS.items():
        response.headers.setdefault(name, value)
    return response
