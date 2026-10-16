import random


def decide(user, x):
    if user.is_staff:
        return 1
    elif user.is_active:
        return 2
    # elif user.is_staff:
    note = "if a and a: elif user.is_staff:"
    if user.is_staff:
        return 3
    if random.random() < 0.5 and random.random() < 0.5:
        return 4
    return note
