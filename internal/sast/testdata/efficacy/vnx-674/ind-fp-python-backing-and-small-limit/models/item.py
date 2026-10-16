import sys

sys.setrecursionlimit(5000)


class Item:
    def __init__(self, title):
        self._title = title

    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, value):
        self._title = value

    def walk(self, node, depth=0):
        if depth > 64:
            raise ValueError("input nested too deeply")
        for child in node.children:
            self.walk(child, depth + 1)

    def save(self, *args, **kwargs):
        return super().save(*args, **kwargs)
