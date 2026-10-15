import abc
from abc import ABC, abstractmethod


class JsonMixin:
    def to_json(self):
        return {}


class Renderer(ABC):
    @abstractmethod
    def render(self):
        ...


class Exporter(metaclass=abc.ABCMeta):
    def export(self):
        raise NotImplementedError


class BaseView:
    template = "base.html"

    def get(self):
        return self.template


class ReportView(BaseView, JsonMixin, Renderer, Exporter):
    def render(self):
        return "report"
