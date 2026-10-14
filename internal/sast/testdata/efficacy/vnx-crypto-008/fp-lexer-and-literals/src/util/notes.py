# if signature == expected_signature: use hmac.compare_digest instead
HELP = "never write signature == expected"


def kind(token_type, digest_size):
    if token_type == TOKEN_NAME:
        return 1
    if digest_size == 32:
        return 2
    return 0
