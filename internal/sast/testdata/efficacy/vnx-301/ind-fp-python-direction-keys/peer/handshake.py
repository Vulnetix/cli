import hashlib
import hmac
import os

from .keys import CLIENT_TO_SERVER_KEY, SERVER_TO_CLIENT_KEY


def respond_to_server(sock):
    challenge = sock.recv(32)
    sock.sendall(hmac.new(CLIENT_TO_SERVER_KEY, challenge, hashlib.sha256).digest())


def challenge_server(sock):
    nonce = os.urandom(32)
    sock.sendall(nonce)
    expected = hmac.new(SERVER_TO_CLIENT_KEY, nonce, hashlib.sha256).digest()
    return hmac.compare_digest(expected, sock.recv(32))
