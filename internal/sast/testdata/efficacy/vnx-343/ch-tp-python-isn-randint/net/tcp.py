import random


class Connection:
    def open(self):
~>        self.isn = self.last_isn + random.randint(1, 64000)
        return self.isn
