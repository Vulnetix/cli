from flask import jsonify
import secrets


def new_captcha_challenge():
    a, b = secrets.randbelow(9), secrets.randbelow(9)
    question = f"{a} + {b}"
    solution = str(a + b)
~>    return jsonify({"question": question, "solution": solution})
