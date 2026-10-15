from dataclasses import dataclass


class Money:
    def __init__(self, cents):
        self.cents = cents

    def __eq__(self, other):
        return self.cents == other.cents

    def __lt__(self, other):
        return self.cents < other.cents


@dataclass(frozen=True)
class Version:
    major: int

    def __lt__(self, other):
        return self.major < other.major


class Euro(Money):
    def __le__(self, other):
        return self.cents <= other.cents


class Sorter:
    def sort(self, items):
        return sorted(items, key=lambda i: i.__lt__)
