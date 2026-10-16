import jwt

# Signature checks switched off on a signed token: VNX-SEC-015 leaves these
# lines to this rule.


def peek(token):
~>    return jwt.decode(token, options={'verify_signature': False})


def peek_kwargs(token):
~>    opts = dict(verify_signature=False, verify_aud=False)
    return jwt.decode(token, SIGNING_KEY, algorithms=["RS256"], options=opts)


def old_style(token):
~>    return jwt.decode(token, SIGNING_KEY, verify = False)


def wrapped(token):
    return jwt.decode(
        token,
        SIGNING_KEY,
~>        verify=False,
    )
