import random


def register(user):
~>    otp = random.randint(100000, 999999)
~>    user.password_salt = str(random.getrandbits(64))
~>    session_id = "%032x" % random.getrandbits(128)
    temp_password = "".join(
~>        random.sample("abcdefghjkmnpqrstuvwxyz23456789", 10)
    )
    user.save()
    return otp, session_id, temp_password
