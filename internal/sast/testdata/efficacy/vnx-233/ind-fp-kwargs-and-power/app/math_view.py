from flask import request


def build_filter(**kwargs):
    return {k: v for k, v in kwargs.items() if v is not None}


@app.route("/square")
def square():
    n = int(request.args.get("n", 2))
    area = n ** 2
    return {"area": area, "filter": build_filter(name=request.args.get("name"), status="open")}
