import hashlib
import hmac

from proto.agent import Agent

KEY = b"k" * 32


class FakePeer:
    def answer(self, challenge):
        return hmac.new(KEY, challenge, hashlib.sha256).digest()


def test_agent_accepts_good_peer():
    nonce = b"n" * 16
    expected = hmac.new(KEY, nonce, hashlib.sha256).digest()
    assert hmac.compare_digest(FakePeer().answer(nonce), expected)
