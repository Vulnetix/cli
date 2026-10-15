def mcrypt_decrypt(cipher, key, data, mode):
    raise NotImplementedError("mcrypt_decrypt( is gone; use cryptography.fernet")

value = mcrypt_decrypt("rijndael-128", key, blob, "cbc")
