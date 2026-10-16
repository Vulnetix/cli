import pyotp


def next_hotp(user):
    hotp = pyotp.HOTP(user.otp_secret)
    user.hotp_counter += 1
    user.save()
    return hotp.at(user.hotp_counter)
