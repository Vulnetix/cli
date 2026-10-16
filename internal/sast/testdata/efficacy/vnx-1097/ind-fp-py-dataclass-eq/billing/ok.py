from dataclasses import dataclass


@dataclass(order=True)
class Price:
    cents: int


class Weight:
    def __init__(self, g):
        self.g = g

    def __eq__(self, other):
        return self.g == other.g

    def __lt__(self, other):
        return self.g < other.g


class Special(Weight):
    def __lt__(self, other):
        return self.g * 2 < other.g
