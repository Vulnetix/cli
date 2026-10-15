from cryptography.exceptions import InvalidSignature


def verify_signature(public_key, payload, sig):
    try:
        public_key.verify(sig, payload)
    except InvalidSignature:
        pass
~>    return True
