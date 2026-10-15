from typing import Generic, TypeVar

T = TypeVar("T")


class JsonHandler:
    content_type = "application/json"

    def render(self, data):
        return data


class XmlHandler:
    content_type = "application/xml"

    def render(self, data):
        return "<x/>"


def build():
~>    class Negotiating(JsonHandler, XmlHandler, Generic[T]):
        def pick(self):
            return self.content_type

    return Negotiating
