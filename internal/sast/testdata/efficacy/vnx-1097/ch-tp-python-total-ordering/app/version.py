import functools


@functools.total_ordering
class Version:
    def __init__(self, text):
        self.parts = tuple(int(p) for p in text.split("."))

~>    def __lt__(self, other):
        return self.parts < other.parts

    def __repr__(self):
        return "Version(%r)" % (".".join(map(str, self.parts)),)
