from base import BaseSession


class AdminSession(BaseSession):
    def elevate(self):
~>        return self._BaseSession__token

    def forget(self):
~>        del self._BaseSession__token
