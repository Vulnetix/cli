import hmac
import marshal

from flask import request

KEY = b"loaded-from-the-environment"


def install_signed():
    blob = request.get_data()
    mac = request.headers.get("X-Signature", "")
    expected = hmac.new(KEY, blob, "sha256").hexdigest()
    if not hmac.compare_digest(mac, expected):
        raise PermissionError("bad signature")
    return marshal.loads(blob)


def roundtrip(obj):
    return marshal.loads(marshal.dumps(obj))
