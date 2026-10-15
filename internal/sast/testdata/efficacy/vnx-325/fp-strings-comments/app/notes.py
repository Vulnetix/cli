# Do not use AES.new(key, AES.MODE_CBC, iv) without an HMAC.
SUPPORTED = "AES/CBC/PKCS5Padding is rejected by the policy"


def describe():
    return "modes.CBC(iv) needs a MAC"
