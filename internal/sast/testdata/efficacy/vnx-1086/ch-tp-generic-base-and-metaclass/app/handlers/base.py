from abc import ABCMeta


~>class Handler(metaclass=ABCMeta):
    def handle(self, event):
        raise NotImplementedError
