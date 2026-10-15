import hmac
import os

PSK = os.environ["AGENT_PSK"].encode()


def answer_peer(sock):
    peer_nonce = sock.recv(32)
~>    sock.sendall(hmac.digest(PSK, peer_nonce, "sha256"))


def challenge_peer(sock):
    my_nonce = os.urandom(32)
    sock.sendall(my_nonce)
    reply = sock.recv(32)
    expected = hmac.digest(PSK, my_nonce, "sha256")
    return hmac.compare_digest(reply, expected)
