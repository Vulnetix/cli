from abc import ABC, abstractmethod
from base import BaseView, Renderer


class JsonMixin:
    def to_json(self):
        return "{}"


class Shape(ABC):
    @abstractmethod
    def area(self): ...


class Named:
    def name(self):
        return "n"


class Plugin:
    def run(self):
        raise NotImplementedError


class ReportView(BaseView, JsonMixin, Renderer):
    pass


class Square(Shape, Named):
    def area(self):
        return 1


class Impl(Named, Plugin):
    pass
