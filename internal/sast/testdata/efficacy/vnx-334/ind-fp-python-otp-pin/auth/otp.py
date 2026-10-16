import secrets


def generate_otp() -> str:
    otp = secrets.randbelow(1000000)
    return f"{otp:06d}"


def generate_pin() -> int:
    pin = secrets.randbelow(10000)
    return pin
