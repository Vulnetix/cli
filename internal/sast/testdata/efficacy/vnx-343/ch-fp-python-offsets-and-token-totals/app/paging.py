import random


def scroll(last_offset):
    offset = last_offset + random.randint(0, 10)
    total_tokens = 0
    total_tokens += random.randint(1, 3)
    return offset, total_tokens
