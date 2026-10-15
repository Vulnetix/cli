import random
import secrets


def forgot_password(user):
    reset_token = secrets.token_urlsafe(32)
    otp_code = secrets.randbelow(900000) + 100000
    rng = random.SystemRandom()
    temp_password = "".join(rng.choice("abcdef0123456789") for _ in range(12))
    retry_delay = random.randint(1, 5)
    send_mail(user.email, reset_token, otp_code, temp_password)
    return retry_delay
