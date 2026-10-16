import secrets


class CSPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.csp_nonce = secrets.token_urlsafe(16)
        response = self.get_response(request)
        response["Content-Security-Policy"] = (
            f"default-src 'self'; script-src 'self' 'nonce-{request.csp_nonce}'"
        )
        return response
