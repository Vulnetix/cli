import random
import time


def fetch(url, attempts=5):
    for attempt in range(attempts):
        try:
            return get(url)
        except IOError:
            time.sleep(2 ** attempt + random.uniform(0, 1))
    for item in queue():
        time.sleep(0.5 if item.priority == "low" else 0.1)
    time.sleep(random.random())
