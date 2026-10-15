from app.handlers.base import Handler


class Kind7Handler(Handler):
    def handle(self, event):
        return event.get('kind7handler')


class Kind8Handler(Handler):
    def handle(self, event):
        return event.get('kind8handler')


class Kind9Handler(Handler):
    def handle(self, event):
        return event.get('kind9handler')


class Kind10Handler(Handler):
    def handle(self, event):
        return event.get('kind10handler')


class Kind11Handler(Handler):
    def handle(self, event):
        return event.get('kind11handler')


class Kind12Handler(Handler):
    def handle(self, event):
        return event.get('kind12handler')


class Kind13Handler(Handler):
    def handle(self, event):
        return event.get('kind13handler')

