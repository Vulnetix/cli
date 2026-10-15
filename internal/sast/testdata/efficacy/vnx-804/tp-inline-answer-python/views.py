from flask import Flask, jsonify, session

app = Flask(__name__)


@app.get("/captcha")
def captcha():
    question, solution = make_challenge()
    session["captcha_solution"] = solution
~>    return jsonify({"question": question, "solution": solution})
