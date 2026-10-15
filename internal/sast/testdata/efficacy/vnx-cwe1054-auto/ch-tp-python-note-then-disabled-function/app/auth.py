import hmac

ADMIN_TOKEN = "rotate-me"


# Old token check, kept until the SSO migration is finished:
~># def check_token(token):
#     if token == ADMIN_TOKEN:
#         return True
#     return hmac.compare_digest(token, ADMIN_TOKEN)


def check_token(token, sso):
    return sso.verify(token)
