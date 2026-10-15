import random
import string


def new_text(length=6):
~>    return "".join(random.choice(string.ascii_uppercase) for _ in range(length))


def make_math():
~>    left = random.randint(1, 9)
~>    right = random.randint(1, 9)
    return f"{left} + {right}", left + right
