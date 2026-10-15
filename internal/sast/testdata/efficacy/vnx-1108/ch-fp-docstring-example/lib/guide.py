"""Helpers for porting scripts.

Avoid writing code like this::

    def tick():
        global counter
        global total
        global seen
        counter += 1

Pass a state object instead.
"""


class State:
    def __init__(self):
        self.counter = 0
