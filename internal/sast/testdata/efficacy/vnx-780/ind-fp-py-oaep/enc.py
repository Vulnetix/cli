from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def wrap(pub, m):
    return pub.encrypt(m, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def sign(priv, m):
    return priv.sign(m, padding.PKCS1v15(), hashes.SHA256())
