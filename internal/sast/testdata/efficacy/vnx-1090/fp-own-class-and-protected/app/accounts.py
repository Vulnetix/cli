class Account:
    def __init__(self, owner, balance):
        self.owner = owner
        self.__balance = balance
        self._limit = 100

    def balance(self):
        return self.__balance

    def merge(self, other: "Account"):
        # explicit mangled form of our own private member
        self.__balance += other._Account__balance

    def __repr__(self):
        return f"{self.__class__.__name__}({self.owner!r})"


class Report:
    def render(self, account):
        data = account.__dict__
        return account._limit, account.balance(), data
