class BaseSession:
    def __init__(self, token):
        self.__token = token

    def token_hint(self):
        return self.__token[:4]


class AdminSession(BaseSession):
    def elevate(self):
~>        tok = self._BaseSession__token
        return tok + ":admin"

    def wipe(self):
~>        del self._BaseSession__token
