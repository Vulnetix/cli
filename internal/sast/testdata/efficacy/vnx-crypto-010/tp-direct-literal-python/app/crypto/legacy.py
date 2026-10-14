from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def encrypt_cbc(key: bytes, data: bytes) -> bytes:
~>    cipher = AES.new(key, AES.MODE_CBC, b"0123456789abcdef")
    return cipher.encrypt(data)


def encrypt_gcm(key, data):
~>    cipher = AES.new(key, AES.MODE_GCM, nonce=b"fixed-nonce!")
    return cipher.encrypt_and_digest(data)


def encrypt_ctr(key, data):
~>    enc = Cipher(algorithms.AES(key), modes.CTR(b"\x00" * 16)).encryptor()
    return enc.update(data) + enc.finalize()


def seal(key, data):
    aesgcm = AESGCM(key)
~>    return aesgcm.encrypt(b"000000000000", data, None)


def seal_chacha(key, data):
~>    return ChaCha20Poly1305(key).encrypt(bytes(12), data, b"")
