from flask import request


def note():
    with open("notes.txt", "a") as fh:
        fh.write(f"{request.form['text']}\n")
    return "ok"
