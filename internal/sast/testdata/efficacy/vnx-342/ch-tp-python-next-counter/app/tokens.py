import itertools


class TokenIssuer:
    def __init__(self):
        self._token_counter = itertools.count(1)

    def issue(self):
~>        token = str(next(self._token_counter))
        return token
