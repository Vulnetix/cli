from Crypto.Cipher import AES


def encrypt_block(key, block):
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def seal(key, data):
    c = AES.new(key, AES.MODE_EAX)
    ct, tag = c.encrypt_and_digest(data)
    return c.nonce, ct, tag
