from .handlers import handle


class Server:
    def dispatch(self, raw):
        return handle(self, raw)
