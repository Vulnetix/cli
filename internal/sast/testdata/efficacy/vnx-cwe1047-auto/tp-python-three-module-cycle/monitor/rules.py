from .notify import send


def evaluate(alert, sample):
    if sample > alert.level:
        send(alert)
        return True
    return False
