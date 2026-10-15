import hashlib
import random
import time
from random import randint


def forgot_password(user):
~>    reset_token = str(random.randint(100000, 999999))
    user.reset_token = reset_token
~>    otp_code = randint(1000, 9999)
~>    user.recovery_key = hashlib.md5(user.email.encode()).hexdigest()
~>    temp_password = "".join(random.choice("abcdef0123456789") for _ in range(8))
    send_mail(user.email, reset_token, otp_code, temp_password)
~>    user.reset_hash = hashlib.sha1(str(time.time()).encode()).hexdigest()
