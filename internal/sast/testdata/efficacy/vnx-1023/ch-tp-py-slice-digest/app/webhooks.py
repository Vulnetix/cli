import hashlib
import hmac


def verify(body: bytes, header_sig: str, secret: bytes) -> bool:
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
~>    return hmac.compare_digest(header_sig[:16], expected[:16])


def check_otp(otp_code: str, submitted: str) -> bool:
~>    return submitted[:4] == otp_code[:4]
