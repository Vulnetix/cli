from flask import request, session

from .wrappers import FormReader


def remember():
    reader = FormReader(request)
    name = reader.get("name")
    greeting = f"hello {name}"
~>    session["greeting"] = greeting
    return "ok"
