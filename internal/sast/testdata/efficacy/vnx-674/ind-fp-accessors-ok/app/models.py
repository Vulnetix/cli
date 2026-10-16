import sys


class User:
    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    def log(self, msg, level=None):
        return self.log(msg, 20)


sys.setrecursionlimit(5000)


def walk(node, depth=0):
    if depth > 100:
        raise ValueError("too deep")
    for child in node.children:
        walk(child, depth + 1)
