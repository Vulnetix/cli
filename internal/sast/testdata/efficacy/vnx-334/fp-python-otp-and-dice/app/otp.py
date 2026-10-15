import secrets


def send_otp(user):
    otp = secrets.randbelow(1000000)
    sms(user, f"{otp:06d}")


def roll():
    return secrets.randbelow(6) + 1
