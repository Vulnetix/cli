# Never call public_key.encrypt(message, padding.PKCS1v15()); use OAEP.
HELP = "rsa.EncryptPKCS1v15 and padding.PKCS1v15() are legacy"


def explain():
    return "Cipher.getInstance(\"RSA/ECB/PKCS1Padding\") is weak"
