import secrets

CSP_TEMPLATE = "default-src 'self'; script-src 'self' 'nonce-__NONCE__'"


def csp_header():
    nonce = secrets.token_urlsafe(16)
    return CSP_TEMPLATE.replace("__NONCE__", nonce), nonce


def apply(response):
    header, nonce = csp_header()
    response.headers["Content-Security-Policy"] = header
    return nonce
