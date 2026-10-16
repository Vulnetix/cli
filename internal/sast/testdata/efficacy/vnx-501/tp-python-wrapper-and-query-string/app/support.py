class Reader:
    def __init__(self, request):
        self.request = request

    def form(self, name):
        return self.request.form.get(name)

    def fixed(self, name):
        return "default"
