class View:
    def dispatch(self, request):
        handler = getattr(self, request.method.lower(), None)
        if handler is None:
            return self.http_method_not_allowed(request)
        return handler(request)

    def column(self, row):
        return getattr(row, "name")
