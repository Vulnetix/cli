import rsa
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa as crsa
from OpenSSL import crypto


def a():
    return crsa.generate_private_key(
        public_exponent=65537,
~>        key_size=1024,
    )


def b():
~>    return RSA.generate(1024)


def c():
~>    pub, priv = rsa.newkeys(512)
    return priv


def d():
    k = crypto.PKey()
~>    k.generate_key(crypto.TYPE_RSA, 1024)
    return k
