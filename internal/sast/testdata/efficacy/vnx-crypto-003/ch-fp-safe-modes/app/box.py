from Crypto.Cipher import AES

MODES_FORBIDDEN = ["ECB"]


def seal(key, data, nonce):
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return c.encrypt_and_digest(data)
