TRUSTED_ORIGINS = {"https://app.example.com"}


class CorsMiddleware:
    def __call__(self, request):
        response = self.get_response(request)
        origin = request.headers.get("Origin")
        if origin in TRUSTED_ORIGINS:
            response["Access-Control-Allow-Origin"] = origin
        return response
