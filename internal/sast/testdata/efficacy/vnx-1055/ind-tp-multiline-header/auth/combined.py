class Authenticator:
    realm = "main"

    def verify(self, token):
        return token == "x"


class Authorizer:
    roles = ["admin"]

    def allow(self, user):
        return user in self.roles


class Auditor:
    def log(self, msg):
        print(msg)


~>class Gateway(
    Authenticator,
    Authorizer,
):
    pass
