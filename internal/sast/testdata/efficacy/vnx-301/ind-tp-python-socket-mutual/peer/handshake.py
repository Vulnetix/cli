import hashlib
import hmac
import os

from .config import LINK_KEY

NONCE_LEN = 32


def respond_to_peer(sock):
    challenge = sock.recv(NONCE_LEN)
~>    response = hmac.new(LINK_KEY, challenge, hashlib.sha256).digest()
    sock.sendall(response)


def challenge_peer(sock):
    nonce = os.urandom(NONCE_LEN)
    sock.sendall(nonce)
    expected = hmac.new(LINK_KEY, nonce, hashlib.sha256).digest()
    answer = sock.recv(len(expected))
    return hmac.compare_digest(expected, answer)
