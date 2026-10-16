class Auditor:
    def __init__(self, store):
        self.store = store

    def reset(self, account):
        # zero the balance without going through withdraw()
~>        account._Account__balance = 0
        self.store.save(account)

    def total(self, accounts):
~>        return sum(a._Account__balance for a in accounts)
