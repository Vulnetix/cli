from flask import Flask, request, session

app = Flask(__name__)


def normalise(hint):
    cleaned = hint.strip()
    return cleaned


@app.route("/basket/mode", methods=["POST"])
def basket_mode():
    coupon = request.form.get("coupon", "")
    retries = 1
    if retries * 10 + 5 > 40:
        mode = "standard"
    else:
        mode = coupon
~>    session["basket.mode"] = mode
    return "ok"


@app.route("/basket/channel", methods=["POST"])
def basket_channel():
    coupon = request.form.get("coupon", "")
    channel = "web" if not coupon else coupon
~>    session["basket.channel"] = channel
    return "ok"


@app.route("/basket/coupon", methods=["POST"])
def basket_coupon():
    coupon = request.form.get("coupon", "")
    fields = {"currency": "EUR"}
    fields["coupon"] = coupon
    code = fields.get("coupon")
~>    session["basket.coupon"] = code
    return "ok"


@app.route("/basket/step", methods=["POST"])
def basket_step():
    coupon = request.form.get("coupon", "")
    steps = [coupon, "review"]
    steps.insert(0, "start")
    step = steps[1]
~>    session["basket.step"] = step
    return "ok"


@app.route("/basket/tier", methods=["POST"])
def basket_tier():
    coupon = request.form.get("coupon", "")
    plan = "gold"
    match plan:
        case "premium" | "gold":
            tier = coupon
        case "basic":
            tier = "standard"
        case _:
            tier = "none"
~>    session["basket.tier"] = tier
    return "ok"


@app.route("/basket/region", methods=["POST"])
def basket_region():
    coupon = request.form.get("coupon", "")
    region = normalise(coupon)
~>    session["basket.region"] = region
    return "ok"


@app.route("/basket/note", methods=["POST"])
def basket_note():
    note = request.form.get("note", "")
    label = "gift"
    label = note
    saved = label
~>    session["basket.label"] = saved
    return "ok"


@app.route("/basket/retry", methods=["POST"])
def basket_retry():
    note = request.form.get("note", "")
    saved = "none"
    for attempt in range(3):
        if attempt == 2:
            saved = note
~>    session["basket.last"] = saved
    return "ok"


@app.route("/basket/fields", methods=["POST"])
def basket_fields():
    coupon = request.form.get("coupon", "")
    fields = {"currency": "EUR"}
    fields["coupon"] = coupon
    currency = fields.get("currency")
    session["basket.currency"] = currency
    code = fields.get("coupon")
~>    session["basket.code"] = code
    return "ok"
