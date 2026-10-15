import random
import string
import time


class InviteService:
    def __init__(self):
~>        self._rng = random.Random(time.time())

    def invite_token(self):
        token = "".join(self._rng.choices(string.ascii_letters, k=24))
        return token
