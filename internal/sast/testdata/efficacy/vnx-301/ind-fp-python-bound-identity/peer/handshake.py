import hashlib
import hmac
import os

from .config import LINK_KEY, NODE_ID


def respond_to_peer(sock):
    challenge = sock.recv(32)
    tag = hmac.new(LINK_KEY, b"responder:" + NODE_ID + challenge, hashlib.sha256).digest()
    sock.sendall(tag)


def challenge_peer(sock, peer_id):
    nonce = os.urandom(32)
    sock.sendall(nonce)
    expected = hmac.new(LINK_KEY, b"responder:" + peer_id + nonce, hashlib.sha256).digest()
    return hmac.compare_digest(expected, sock.recv(32))
