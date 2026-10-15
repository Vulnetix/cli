import hmac
import logging

from cryptography.exceptions import InvalidSignature
from itsdangerous import BadSignature

log = logging.getLogger(__name__)


def load_update(public_key, blob, signature):
    try:
        public_key.verify(signature, blob)
~>    except InvalidSignature:
        pass
    return blob


def read_cookie(serializer, value):
    data = None
    try:
        data = serializer.loads(value)
    except BadSignature as exc:
        log.warning("bad cookie signature: %s", exc)
    return data


def webhook(body, header, key):
    expected = hmac.new(key, body, "sha256").hexdigest()
~>    hmac.compare_digest(expected, header)
    return process(body)


def plugin(key, sig, data):
    try:
        key.verify(sig, data)
~>    except Exception:
        pass
    run(data)
