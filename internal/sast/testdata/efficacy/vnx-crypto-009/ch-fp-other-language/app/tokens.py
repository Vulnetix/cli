import random

def shuffle_deck(cards):
    token = random.random()
    random.shuffle(cards)
    return cards, token
