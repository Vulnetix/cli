from flask import Flask, request, session

app = Flask(__name__)


def default_currency(hint):
    return "EUR"


@app.route("/cart/mode", methods=["POST"])
def cart_mode():
    coupon = request.form.get("coupon", "")
    retries = 4
    if retries * 10 + 5 > 40:
        mode = "standard"
    else:
        mode = coupon
    session["cart.mode"] = mode
    return "ok"


@app.route("/cart/channel", methods=["POST"])
def cart_channel():
    coupon = request.form.get("coupon", "")
    version = 3
    channel = "web" if version - 3 == 0 else coupon
    session["cart.channel"] = channel
    return "ok"


@app.route("/cart/currency", methods=["POST"])
def cart_currency():
    coupon = request.form.get("coupon", "")
    fields = {"currency": "EUR"}
    fields["coupon"] = coupon
    currency = fields.get("currency")
    session["cart.currency"] = currency
    return "ok"


@app.route("/cart/step", methods=["POST"])
def cart_step():
    coupon = request.form.get("coupon", "")
    steps = [coupon, "review"]
    steps.insert(0, "start")
    step = steps[-1]
    session["cart.step"] = step
    return "ok"


@app.route("/cart/tier", methods=["POST"])
def cart_tier():
    coupon = request.form.get("coupon", "")
    plan = "basic"
    match plan:
        case "premium" | "gold":
            tier = coupon
        case "basic":
            tier = "standard"
        case _:
            tier = coupon
    session["cart.tier"] = tier
    return "ok"


@app.route("/cart/region", methods=["POST"])
def cart_region():
    coupon = request.form.get("coupon", "")
    region = default_currency(coupon)
    session["cart.region"] = region
    return "ok"


@app.route("/cart/note", methods=["POST"])
def cart_note():
    note = request.form.get("note", "")
    label = "gift"
    saved = label
    label = note
    session["cart.label"] = saved
    return "ok"
