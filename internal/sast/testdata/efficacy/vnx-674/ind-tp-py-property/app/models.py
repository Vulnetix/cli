class User:
    def __init__(self, name):
        self._name = name

    @property
    def name(self):
~>        return self.name

    @name.setter
    def name(self, value):
~>        self.name = value
