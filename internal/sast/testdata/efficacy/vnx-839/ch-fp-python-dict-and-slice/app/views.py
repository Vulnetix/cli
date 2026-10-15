from flask import request

RESULTS = list(range(100))


def top():
    n = int(request.args.get("n", "10"))
    if n > 50:
        n = 50
    return {"items": RESULTS[:n]}


def page():
    p = int(request.args.get("p", "0"))
    if p > 9:
        p = 9
    print("page", p)
    return {"page": p}
