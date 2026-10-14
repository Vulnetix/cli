from jwt import decode
import jwt


def get_identity(token):
~>    return decode(token, options={"verify_signature":False, "verify_exp":False}).get("identity")


def legacy_claims(token, key):
~>    return jwt.decode(token, key, verify=False)
