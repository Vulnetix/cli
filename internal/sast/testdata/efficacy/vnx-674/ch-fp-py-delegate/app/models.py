import sys

sys.setrecursionlimit(5000)


class Wrapper:
    def get(self, key):
        return self.get(key, None)

    def read(self, n):
        return self._inner.read(n)

    @property
    def name(self):
        return self._name
