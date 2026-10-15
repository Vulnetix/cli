import random


def sample_request(vocab):
    max_tokens = random.randint(64, 256)
    token_count = random.randint(1, 10)
    tokens = random.sample(vocab, 5)
    temperature = random.uniform(0.1, 0.9)
    return max_tokens, token_count, tokens, temperature
