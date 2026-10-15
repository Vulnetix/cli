import os
import time

LOG_DIR = "/var/log/app"
MAX_AGE = 30 * 86400


def rotate():
    if time.time() - os.path.getmtime(os.path.join(LOG_DIR, "2024-01-01.log")) > MAX_AGE:
        os.remove(os.path.join(LOG_DIR, "2024-01-01.log"))
