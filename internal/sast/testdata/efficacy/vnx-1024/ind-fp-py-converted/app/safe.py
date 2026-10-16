import os
from flask import request

def a():
    level = request.args.get("level", type=int)
    if level == 1:
        return "x"

def b():
    n = int(input("n: "))
    return n == 3

def c():
    workers = os.getenv("WORKERS", 4)
    return workers == 4

def d():
    raw = request.args.get("level")
    raw = int(raw)
    return raw == 1

def e():
    return len(input()) == 5

def f():
    v = input()
    return v > 3  # ordering, not equality
# if input() == 1:
