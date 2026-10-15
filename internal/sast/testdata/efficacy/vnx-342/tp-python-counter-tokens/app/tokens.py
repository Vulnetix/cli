import itertools

_ids = itertools.count(1)
_last_token = 0


def new_api_token():
    global _last_token
~>    _last_token += 1
    return "tok-%d" % _last_token


def create_session(user):
~>    session_id = str(next(_ids))
    user.session_id = session_id
    return session_id


class Otp:
    def __init__(self):
        self.prev_otp = 100000

    def issue(self):
~>        self.prev_otp = self.prev_otp + 1
        return self.prev_otp
