import hvac


class VaultClient:
    def __init__(self, url, vault_token):
        self.vault_token = vault_token
        self.client = hvac.Client(url=url, token=vault_token)

    def login(self):
        if not self.client.is_authenticated():
~>            raise RuntimeError(
                f"vault login failed using token {self.vault_token}"
            )

    def connect_db(self, user, db_password):
        if not user:
~>            raise ConnectionError("cannot log in as %s:%s" % (user, db_password))
