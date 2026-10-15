class Account:
    @property
    def balance(self):
        return self._balance

    @balance.setter
    def balance(self, value):
~>        self.balance = value
