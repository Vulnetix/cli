# Never do this: hashlib.md5(password.encode()).hexdigest()
WARNING = "hashlib.sha1(password) is not a password hash"


def explain():
    print("Do not call md5(password) for storage")
    return WARNING
