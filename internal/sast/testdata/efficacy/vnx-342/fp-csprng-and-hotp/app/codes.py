import itertools
import secrets

import pyotp

_ids = itertools.count(1)


def session_id():
    session_id = f"{next(_ids)}-{secrets.token_hex(16)}"
    return session_id


def otp_for(secret, counter):
    otp = pyotp.HOTP(secret).at(counter + 1)
    return otp
