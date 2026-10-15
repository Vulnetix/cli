import hmac

from cryptography.exceptions import InvalidSignature


def load_update(public_key, blob, signature):
    try:
        public_key.verify(signature, blob)
    except InvalidSignature:
        raise PermissionError("update signature invalid")
    return blob


def check(public_key, blob, signature):
    try:
        public_key.verify(signature, blob)
    except InvalidSignature:
        return False
    return True


def webhook(body, header, key):
    expected = hmac.new(key, body, "sha256").hexdigest()
    if not hmac.compare_digest(expected, header):
        abort(401)


def cleanup(path):
    try:
        os.remove(path)
    except Exception:
        pass
