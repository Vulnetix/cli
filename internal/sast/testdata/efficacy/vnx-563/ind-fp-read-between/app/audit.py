import logging

log = logging.getLogger(__name__)


def record(user, action):
    message = action.describe()
    log.info(f"{user.id}: {message}")
    message = action.summary()
    return message


def counter(start):
    count = start * 2

    def bump():
        nonlocal count
        count += 1
        return count

    count = bump()
    return count
