import random


class TokenIssuer:
    def __init__(self, start):
        self.current_token = start

    def issue(self):
~>        self.current_token += random.randint(1, 500)
        return self.current_token
