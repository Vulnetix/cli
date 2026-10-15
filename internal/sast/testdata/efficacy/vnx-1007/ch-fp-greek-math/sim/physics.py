import math

Δt = 0.01
λ = 2.5


def step(x, v):
    return x + v * Δt, v - λ * x * Δt


def omega(k, m):
    ω = math.sqrt(k / m)
    return ω
