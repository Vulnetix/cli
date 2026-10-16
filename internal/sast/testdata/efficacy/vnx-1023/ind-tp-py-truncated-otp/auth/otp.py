def verify_otp(submitted, expected_otp):
~>    return submitted[:6] == expected_otp[:6]
