import hashlib
import hmac
import os

SHARED_KEY = load_key()


def answer_challenge(conn):
    challenge = conn.recv(32)
    conn.sendall(hmac.new(SHARED_KEY, MY_ID + challenge, hashlib.sha256).digest())


def authenticate_peer(conn, peer_id):
    nonce = os.urandom(32)
    conn.sendall(nonce)
    response = conn.recv(32)
    expected = hmac.new(SHARED_KEY, peer_id + nonce, hashlib.sha256).digest()
    return hmac.compare_digest(expected, response)
