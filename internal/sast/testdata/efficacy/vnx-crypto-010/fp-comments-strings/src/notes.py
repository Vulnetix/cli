"""Crypto helpers.

Never write AES.new(key, AES.MODE_CBC, b"0000000000000000") in production.
"""
import os

from Crypto.Cipher import AES

# cipher = AES.new(key, AES.MODE_CBC, b"0123456789abcdef")
HELP = 'example: AES.new(key, AES.MODE_CBC, b"0123456789abcdef")'


def encrypt(key, data):
    iv = os.urandom(16)  # not b"\x00" * 16
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(data)
