from Crypto.Cipher import DES3 as TripleDES
from Crypto.Cipher import CAST
from cryptography.hazmat.primitives.ciphers import algorithms


def a(key, iv):
~>    return TripleDES.new(key, TripleDES.MODE_CBC, iv)


def b(key):
~>    return CAST.new(key, CAST.MODE_EAX)


def c(key):
~>    return algorithms.CAST5(key)
