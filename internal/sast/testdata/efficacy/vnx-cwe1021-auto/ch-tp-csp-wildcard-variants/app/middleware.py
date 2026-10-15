from django.utils.deprecation import MiddlewareMixin


class EmbedMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
~>        response["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'self' *"
        return response


def widget_headers(response):
~>    response.headers["Content-Security-Policy"] = f"frame-ancestors https: ; script-src 'self'"
~>    del response.headers["X-Frame-Options"]
    return response
