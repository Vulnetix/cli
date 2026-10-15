class Basket:
    def __init__(self, x=[]):
        self.items = x


def collect(item, seen={}):
    seen[item] = True
    return seen
