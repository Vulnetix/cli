import random
import secrets


def shuffled_questions(questions, seed):
    rng = random.Random(seed)
    rng.shuffle(questions)
    return questions


def reset_token() -> str:
    return secrets.token_urlsafe(32)
