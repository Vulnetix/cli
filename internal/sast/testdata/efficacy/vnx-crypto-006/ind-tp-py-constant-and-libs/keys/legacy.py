import rsa as pyrsa
from Crypto.PublicKey import RSA
from OpenSSL import crypto

LEGACY_BITS = 1024


def device_key():
~>    return RSA.generate(LEGACY_BITS)


def quick_pair():
~>    pub, priv = pyrsa.newkeys(512)
    return pub, priv


def openssl_key():
    key = crypto.PKey()
~>    key.generate_key(crypto.TYPE_RSA, 1024)
    return key
