from Crypto.Cipher import AES

~>key = b"Rq7Lx2Mz9Pk4Wn8T"


def seal(data):
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ct, tag
