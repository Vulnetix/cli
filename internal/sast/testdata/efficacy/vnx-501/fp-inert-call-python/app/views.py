from flask import Flask, request, session

app = Flask(__name__)


def default_mode(hint):
    modes = ModeBook.standard()
    chosen = modes.entry("standard")
    return chosen


@app.route("/cart/mode", methods=["POST"])
def cart_mode():
    coupon = request.form.get("coupon", "")
    mode = default_mode(coupon)
    session["cart.mode"] = mode
    return "ok"


@app.route("/cart/channel", methods=["POST"])
def cart_channel():
    coupon = request.form.get("coupon", "")
    book = ModeBook.standard()
    channel = book.entry("web")
    session["cart.channel"] = channel
    return "ok"
