from .accounts import Account


class Auditor:
    def __init__(self, ledger):
        self.ledger = ledger

    def inspect(self, account: Account) -> int:
~>        return account._Account__balance

    def reset(self, account):
~>        account._Account__balance = 0
        self.ledger.record(account.owner, "reset")

    def total(self, accounts):
~>        return sum(a._Account__balance for a in accounts)
