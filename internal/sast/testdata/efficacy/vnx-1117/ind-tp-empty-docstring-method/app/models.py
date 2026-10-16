class Account:
    def __init__(self, owner):
        self.owner = owner

~>    def close(self, reason):
        """"""
        self.owner = None
        return reason
