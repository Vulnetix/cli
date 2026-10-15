import secrets


def csp_middleware(get_response):
    def middleware(request):
        nonce = secrets.token_urlsafe(16)
        request.csp_nonce = nonce
        response = get_response(request)
        response["Content-Security-Policy"] = f"script-src 'nonce-{nonce}'"
        response["X-Alt"] = "script-src 'nonce-%s'" % nonce
        response["X-Alt2"] = "script-src 'nonce-" + nonce + "'"
        return response
    return middleware
