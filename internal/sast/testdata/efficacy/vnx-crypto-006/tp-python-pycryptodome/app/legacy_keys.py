import rsa as pyrsa
from Crypto.PublicKey import RSA
from OpenSSL import crypto


def make():
~>    key = RSA.generate(1024)
    return key.export_key()


def make_kw():
~>    return RSA.generate(bits=1536)


def python_rsa():
~>    pub, priv = pyrsa.newkeys(512)
    return pub, priv


def openssl_key():
    pkey = crypto.PKey()
~>    pkey.generate_key(crypto.TYPE_RSA, 1024)
    return pkey
