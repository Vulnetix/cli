class Ledger:
    def __init__(self):
        self.__entries = []

    def add(self, e):
        self._Ledger__entries.append(e)
        self.__entries.append(e)

    def count(self):
        return len(getattr(self, "_Ledger__entries"))
