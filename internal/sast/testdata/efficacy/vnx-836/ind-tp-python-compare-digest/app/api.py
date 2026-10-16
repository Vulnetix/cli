import hmac

def check(request, user):
    supplied = request.json["pwd_hash"]
~>    return hmac.compare_digest(user.hashed_password, supplied)
