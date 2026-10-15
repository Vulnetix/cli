# Token verification

Never pass `ignoreExpiration: true` to `jwt.verify`, and never set
`options={"verify_exp": False}` when calling PyJWT. Ruby callers must keep
`verify_expiration: true`.
