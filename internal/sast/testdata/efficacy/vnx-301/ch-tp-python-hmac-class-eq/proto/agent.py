import hashlib
import hmac
import secrets


class Agent:
    def __init__(self, psk: bytes):
        self.psk = psk

    def on_challenge(self, sock):
        challenge = sock.recv(16)
~>        tag = hmac.HMAC(self.psk, challenge, hashlib.sha256).digest()
        sock.send(tag)

    def challenge_peer(self, sock):
        nonce = secrets.token_bytes(16)
        sock.send(nonce)
        expected = hmac.HMAC(self.psk, nonce, hashlib.sha256).digest()
        return sock.recv(32) == expected
