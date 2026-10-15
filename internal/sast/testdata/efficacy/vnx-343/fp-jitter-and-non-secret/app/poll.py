import random


class Poller:
    def schedule(self, last_poll):
        self.retry_delay += random.uniform(0, 1)
        next_poll = last_poll + random.randint(1, 5)
        total = 0
        total += random.randint(1, 6)
        self.token_count += random.randint(1, 3)
        return next_poll
