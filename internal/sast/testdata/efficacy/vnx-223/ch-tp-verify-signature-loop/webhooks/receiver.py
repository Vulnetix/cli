import hmac
import hashlib

from cryptography.exceptions import InvalidSignature


def process(events, public_key):
    accepted = []
    for event in events:
        try:
            public_key.verify(event.signature, event.body)
            accepted.append(event)
~>        except InvalidSignature:
            continue
    return accepted
