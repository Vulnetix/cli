import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEY = @@sample:C[h]aC[h]a2[0]Po[l]y1[3]05[.]ge[n]er[a]te[_]ke[y]@@()
NONCE = os.urandom(12)


def seal(data: bytes) -> bytes:
~>    return ChaCha20Poly1305(KEY).encrypt(NONCE, data, None)
