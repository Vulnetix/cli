import base64
from @@sample:c[r]yp[t]og[r]ap[h]y[.][h]az[m]at[.]pr[i]mi[t]iv[e]s[.][k]df[.]pb[k]df[2]@@ import PBKDF2HMAC


def seal(master_password, salt, data):
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=600000)
    key = @@sample:b[a]se[6]4[.][u]rl[s]af[e][_]b[6]4e[n]co[d]e@@(kdf.derive(master_password.encode()))
    token = Fernet(key).encrypt(data)
    encoded_salt = base64.b64encode(salt)
    return token, encoded_salt
