import hmac

from cryptography.exceptions import InvalidSignature
from itsdangerous import BadSignature, URLSafeSerializer

serializer = URLSafeSerializer("secret-key")


def check_firmware(public_key, signature, blob):
    try:
        public_key.verify(signature, blob)
~>    except InvalidSignature:
        pass
    return blob


def read_cookie(value):
    data = value
    try:
        data = serializer.loads(value)
~>    except BadSignature:
        log.warning("bad cookie signature")
    return data


def check_hook(expected, received):
~>    hmac.compare_digest(expected, received)
