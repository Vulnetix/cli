import hashlib


~>def hash_password(raw):
    """"""
    return hashlib.sha256(raw.encode()).hexdigest()


~>def load_user(uid):
    '''TODO'''
    return {"id": uid}


class Session:
~>    def refresh(self, token):
        """..."""
        self.token = token

~>    async def close(self):
        """Docstring."""
        self.token = None
