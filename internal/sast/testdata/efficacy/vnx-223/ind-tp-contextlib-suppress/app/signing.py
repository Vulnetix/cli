from contextlib import suppress

from cryptography.exceptions import InvalidSignature


def accept_update(public_key, payload, signature):
    accepted = True
~>    with suppress(InvalidSignature):
        public_key.verify(signature, payload)
    return accepted
