import random
import time


def refresh_session(client):
    for attempt in range(5):
        if client.refresh():
            return True
        time.sleep(random.uniform(0.5, 1.5) * attempt)
    return False


def pick_mirror(mirrors):
    random.shuffle(mirrors)
    # never use random.choice for a password
    return mirrors[0]
