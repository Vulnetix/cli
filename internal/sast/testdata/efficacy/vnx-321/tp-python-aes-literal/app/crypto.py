import hmac
from Crypto.Cipher import AES
from cryptography.fernet import Fernet

~>cipher = AES.new(b"0123456789abcdef", AES.MODE_GCM)
~>f = Fernet(b"@@sample:q[3]Zk[1]v9[m]0Y[d]2c[X]bR[8]sT[n]Pw[L]u5[e]Ha[J]iG[o]4F[y]Kl[M]xN[z]VA@@=")
~>mac = hmac.new(b"static-hmac-secret", msg, "sha256")
~>ENCRYPTION_KEY = b"k8Jd92LsQm4Zt7Vw"
