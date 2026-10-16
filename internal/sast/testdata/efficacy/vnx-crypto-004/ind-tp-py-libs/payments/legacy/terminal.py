from Crypto.Cipher import ARC4, Blowfish
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def pin_block(key: bytes, iv: bytes, block: bytes) -> bytes:
~>    enc = Cipher(algorithms.TripleDES(key), modes.CBC(iv)).encryptor()
    return enc.update(block) + enc.finalize()


def stream_obfuscate(key: bytes, data: bytes) -> bytes:
~>    return ARC4.new(key).encrypt(data)


def legacy_box(key: bytes, iv: bytes):
~>    return Blowfish.new(key, Blowfish.MODE_CBC, iv)
