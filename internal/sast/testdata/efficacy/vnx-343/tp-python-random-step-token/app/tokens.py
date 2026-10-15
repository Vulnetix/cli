import random
import secrets


class TokenSequence:
    def next_token(self):
~>        self.last_token += random.randint(1, 1000)
        return self.last_token


def reset_code(prev_code):
~>    reset_code = prev_code + random.randrange(10, 99)
    return reset_code


def rotate(last_session):
~>    session_id = last_session + secrets.randbelow(256)
    return session_id


def new_api_key(current):
~>    step = current + random.getrandbits(8)
    api_key = "k%08d" % step
    return api_key
