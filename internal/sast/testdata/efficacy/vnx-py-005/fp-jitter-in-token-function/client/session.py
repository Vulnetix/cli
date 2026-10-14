import random
import time


class Client:
    def refresh_token(self):
        time.sleep(random.uniform(0, 1.5))
        if random.random() < 0.1:
            self.log("refreshing")
        return self._fetch_new_token()
