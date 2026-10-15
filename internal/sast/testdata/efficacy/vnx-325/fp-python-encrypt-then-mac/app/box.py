import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def encrypt(enc_key, mac_key, iv, data):
    ct = AES.new(enc_key, AES.MODE_CBC, iv).encrypt(pad(data, 16))
    tag = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return iv + ct + tag


def encrypt_gcm(key, data):
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ct
