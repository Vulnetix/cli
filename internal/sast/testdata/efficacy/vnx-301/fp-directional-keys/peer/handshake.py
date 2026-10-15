import hashlib
import hmac
import os


def answer_challenge(conn):
    challenge = conn.recv(32)
    conn.sendall(hmac.new(CLIENT_TO_SERVER_KEY, challenge, hashlib.sha256).digest())


def authenticate_peer(conn):
    nonce = os.urandom(32)
    conn.sendall(nonce)
    response = conn.recv(32)
    expected = hmac.new(SERVER_TO_CLIENT_KEY, nonce, hashlib.sha256).digest()
    return hmac.compare_digest(expected, response)
