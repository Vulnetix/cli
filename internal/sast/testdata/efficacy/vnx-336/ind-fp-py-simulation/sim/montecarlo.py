import random
import statistics


def estimate_pi(samples=100_000, seed=42):
    random.seed(seed)
    inside = 0
    for _ in range(samples):
        x, y = random.random(), random.random()
        if x * x + y * y <= 1.0:
            inside += 1
    return 4.0 * inside / samples


def bootstrap_mean(values, rounds=500):
    rng = random.Random(1234)
    means = [statistics.mean(rng.choices(values, k=len(values))) for _ in range(rounds)]
    return statistics.mean(means)
