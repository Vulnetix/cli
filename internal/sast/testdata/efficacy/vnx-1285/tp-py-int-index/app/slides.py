from flask import Flask, request

app = Flask(__name__)
SLIDES = load_slides()


@app.route("/slide")
def slide():
    idx = int(request.args.get("index", 0))
~>    return SLIDES[idx]


@app.route("/answer", methods=["POST"])
def answer(question):
    choice = int(request.form["choice"])
    title = question.title
~>    selected = question.options[choice]
    return {"title": title, "selected": selected}
