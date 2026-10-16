import functools


@functools.total_ordering
class Money:
    def __init__(self, cents, currency="USD"):
        self.cents = cents
        self.currency = currency

~>    def __lt__(self, other):
        return self.cents < other.cents

    def __repr__(self):
        return f"Money({self.cents})"
