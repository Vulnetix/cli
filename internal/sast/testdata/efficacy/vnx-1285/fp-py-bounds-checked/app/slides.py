from flask import abort, request

SLIDES = []


def slide():
    idx = int(request.args.get("index", 0))
    if idx < 0 or idx >= len(SLIDES):
        abort(404)
    return SLIDES[idx]


def answer(question):
    choice = int(request.form["choice"])
    if not 0 <= choice < len(question.options):
        abort(400)
    return question.options[choice]


def page(rows):
    offset = int(request.args.get("offset", 0))
    return rows[offset:offset + 20]
