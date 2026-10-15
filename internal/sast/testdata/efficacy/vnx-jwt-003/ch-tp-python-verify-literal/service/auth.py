import jwt


def verify(token):
~>    return jwt.decode(token, "@@sample:s[3]rv[1]ce[-]hm[a]c[-][k]3y@@", algorithms=["HS256"])
