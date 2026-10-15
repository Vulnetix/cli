class Ledger:
    def __init__(self):
        self.__entries = []

    def add(self, entry):
        self.__entries.append(entry)


class InvoiceExporter:
    def __init__(self, ledger):
        self.ledger = ledger

    def rows(self):
~>        return list(self.ledger._Ledger__entries)

    def reset(self):
~>        self.ledger._Ledger__entries = []
