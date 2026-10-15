import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from @@sample:c[r]yp[t]og[r]ap[h]y[.][h]az[m]at[.]pr[i]mi[t]iv[e]s[.][k]df[.]pb[k]df[2]@@ import PBKDF2HMAC

~>APP_SALT = b"vault-app-salt-v1"


def key_for(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
~>        salt=b"0123456789abcdef",
        iterations=480_000,
    )
    return @@sample:b[a]se[6]4[.][u]rl[s]af[e][_]b[6]4e[n]co[d]e@@(kdf.derive(passphrase.encode()))


def legacy_key(passphrase: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode(), APP_SALT, 100_000)
