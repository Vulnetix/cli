MAX_OTP_ATTEMPTS = 3


def verify_login_code(user, code):
    otp = OneTimeCode.objects.get(user=user, purpose="login")
    if otp.attempts >= MAX_OTP_ATTEMPTS:
        otp.is_active = False
        otp.save()
        return False
    if otp.code != code:
        otp.attempts += 1
        otp.save()
        return False
    return True
