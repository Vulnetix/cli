import functools


@functools.total_ordering
class Money:
    def __init__(self, cents, currency):
        self.cents = cents
        self.currency = currency

~>    def __lt__(self, other):
        return self.cents < other.cents

    def __hash__(self):
        return hash((self.cents, self.currency))


class Ticket(object):
    def __init__(self, rank):
        self.rank = rank

~>    def __gt__(self, other):
        return self.rank > other.rank

    def __lt__(self, other):
        return self.rank < other.rank
