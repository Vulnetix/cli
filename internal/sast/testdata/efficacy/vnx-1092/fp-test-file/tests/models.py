from flask import request


def fake_order():
    return {"note": request.args.get("note")}
