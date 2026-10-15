def check(header):
    if header.get("alg", "").lower() == "none":
        raise InvalidTokenError("unsigned tokens are rejected")
    if header["algorithm"] == "none":
        raise InvalidTokenError("unsigned")
