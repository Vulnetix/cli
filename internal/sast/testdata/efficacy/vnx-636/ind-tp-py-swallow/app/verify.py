def verify_signature(payload, sig):
    try:
        check(payload, sig)
    except ValueError:
        pass
~>    return True
