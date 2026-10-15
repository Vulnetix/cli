from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def seal_eax(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ct


def seal_gcm(key, nonce, data):
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    return enc.update(data) + enc.finalize() + enc.tag


def seal_aesgcm(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)


def seal_chacha(key, nonce, data):
    return ChaCha20Poly1305(key).encrypt(nonce, data, None)


def seal_siv(key, data):
    return AES.new(key, AES.MODE_SIV).encrypt_and_digest(data)
