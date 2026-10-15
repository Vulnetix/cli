class Card:
    RANKS = "23456789TJQKA"

    def __init__(self, rank):
        self.rank = rank

    def __lt__(self, other):
        return self.RANKS.index(self.rank) < self.RANKS.index(other.rank)

    def __gt__(self, other):
        return other < self

    def __eq__(self, other):
        return isinstance(other, Card) and self.rank == other.rank

    def __hash__(self):
        return hash(self.rank)
