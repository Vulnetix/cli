import random
import string


def send_login_code(user):
~>    otp = "".join(random.choices(string.digits, k=6))
    cache.set(f"otp:{user.id}", otp, 300)
~>    user.temp_password = str(random.randint(10000000, 99999999))
    user.save()
