import jwt


def read(token, key):
~>    opts = {'verify_iss' : False}
~>    return jwt.decode(token, key, algorithms=["RS256"], options={ 'verify_aud':False })
