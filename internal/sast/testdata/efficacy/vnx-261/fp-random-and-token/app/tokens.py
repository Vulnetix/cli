import base64
import os


def reset_token(user):
    token = @@sample:b[a]se[6]4[.][u]rl[s]af[e][_]b[6]4e[n]co[d]e@@(os.urandom(32)).decode()
    user.password_reset_token = token
    return token
