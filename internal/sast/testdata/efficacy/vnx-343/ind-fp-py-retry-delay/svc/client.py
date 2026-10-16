import random
import time


class Client:
    def __init__(self):
        self.retry_delay = 0.5

    def backoff(self):
        self.retry_delay += random.uniform(0, 1)
        time.sleep(self.retry_delay)
