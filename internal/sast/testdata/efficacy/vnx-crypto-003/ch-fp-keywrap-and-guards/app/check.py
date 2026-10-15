from Crypto.Cipher import AES


def check(mode):
    if mode == AES.MODE_ECB:
        raise ValueError("ECB is not allowed")
    return mode
