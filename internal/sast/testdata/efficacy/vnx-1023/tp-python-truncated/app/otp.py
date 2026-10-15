import hmac


def verify(expected_otp, submitted):
~>    return submitted[:6] == expected_otp[:6]


def verify_sig(signature, computed):
~>    if signature == computed[:16]:
        return True
~>    return hmac.compare_digest(signature[:8], computed[:8])
