from app.handlers.base import Handler


class Kind0Handler(Handler):
    def handle(self, event):
        return event.get('kind0handler')


class Kind1Handler(Handler):
    def handle(self, event):
        return event.get('kind1handler')


class Kind2Handler(Handler):
    def handle(self, event):
        return event.get('kind2handler')


class Kind3Handler(Handler):
    def handle(self, event):
        return event.get('kind3handler')


class Kind4Handler(Handler):
    def handle(self, event):
        return event.get('kind4handler')


class Kind5Handler(Handler):
    def handle(self, event):
        return event.get('kind5handler')


class Kind6Handler(Handler):
    def handle(self, event):
        return event.get('kind6handler')

