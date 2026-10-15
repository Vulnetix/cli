class User:
    def __init__(self, name):
        self._name = name

    @property
    def name(self):
~>        return self.name

    @property
    def email(self) -> str:
~>        return self.email.lower()

    def full(self, sep):
~>        return self.full(sep)
