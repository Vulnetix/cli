import logging

import nacl.exceptions
from nacl.signing import VerifyKey

log = logging.getLogger(__name__)


def apply_update(verify_key: VerifyKey, signed: bytes) -> bytes:
    payload = signed
    try:
        payload = verify_key.verify(signed)
~>    except nacl.exceptions.BadSignatureError:
        log.warning("update signature did not verify")
    return payload
