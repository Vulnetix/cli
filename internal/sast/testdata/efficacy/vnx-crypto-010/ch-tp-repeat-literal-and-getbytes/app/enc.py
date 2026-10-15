from Crypto.Cipher import AES

def seal(key, data):
~>    cipher = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
    return cipher.encrypt(data)

def seal2(key, data):
~>    iv = "fedcba9876543210".encode()
    c = AES.new(key, AES.MODE_CFB, iv)
    return c.encrypt(data)
