import base64
import hashlib

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def accept(key):
    digest = hashlib.sha1((key + WS_GUID).encode()).digest()
    return base64.b64encode(digest).decode()


def digest_auth_cnonce(nonce):
    return hashlib.sha1(nonce, usedforsecurity=False).hexdigest()[:16]
