import random
import secrets


def backoff(attempt):
    delay = random.randint(1, 30) * attempt
    return delay


def pick_shard(shards):
    return shards[random.randrange(len(shards))]


def issue_token():
    token = secrets.token_hex(16)
    idx = random.randint(0, 9)
    return token, idx


def big_key():
    key = secrets.randbits(256)
    return key
