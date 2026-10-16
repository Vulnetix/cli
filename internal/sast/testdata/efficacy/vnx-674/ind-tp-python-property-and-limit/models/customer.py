import sys

~>sys.setrecursionlimit(100000)


class Customer:
    def __init__(self, name, email):
        self._name = name
        self._email = email

    @property
    def name(self):
~>        return self.name

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, value):
~>        self.email = value

    def lookup(self, key):
~>        return self.lookup(key)
