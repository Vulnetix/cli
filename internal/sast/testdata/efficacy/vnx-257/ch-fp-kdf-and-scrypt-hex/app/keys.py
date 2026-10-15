import base64

from cryptography.fernet import Fernet
from @@sample:c[r]yp[t]og[r]ap[h]y[.][h]az[m]at[.]pr[i]mi[t]iv[e]s[.][k]df[.]pb[k]df[2]@@ import PBKDF2HMAC


def fernet_for(password, salt):
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=480000)
    key = @@sample:b[a]se[6]4[.][u]rl[s]af[e][_]b[6]4e[n]co[d]e@@(kdf.derive(password.encode()))
    return Fernet(key)


def digest(password):
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.b64encode(hashed)
