from app.handlers.base import Handler


class Kind14Handler(Handler):
    def handle(self, event):
        return event.get('kind14handler')


class Kind15Handler(Handler):
    def handle(self, event):
        return event.get('kind15handler')


class Kind16Handler(Handler):
    def handle(self, event):
        return event.get('kind16handler')


class Kind17Handler(Handler):
    def handle(self, event):
        return event.get('kind17handler')


class Kind18Handler(Handler):
    def handle(self, event):
        return event.get('kind18handler')


class Kind19Handler(Handler):
    def handle(self, event):
        return event.get('kind19handler')


class Kind20Handler(Handler):
    def handle(self, event):
        return event.get('kind20handler')

