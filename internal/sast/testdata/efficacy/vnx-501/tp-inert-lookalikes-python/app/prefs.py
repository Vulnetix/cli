from flask import Flask, request, session

app = Flask(__name__)


def mode_for(hint):
    modes = ModeBook.standard()
    chosen = modes.entry(hint)
    return chosen


@app.route("/prefs/mode", methods=["POST"])
def pref_mode():
    coupon = request.form.get("coupon", "")
    mode = mode_for(coupon)
~>    session["prefs.mode"] = mode
    return "ok"


@app.route("/prefs/channel", methods=["POST"])
def pref_channel():
    coupon = request.form.get("coupon", "")
    book = ModeBook.standard()
    channel = book.entry(coupon)
~>    session["prefs.channel"] = channel
    return "ok"


@app.route("/prefs/region", methods=["POST"])
def pref_region():
    scoped = ModeBook(request.form.get("scope", ""))
    region = scoped.entry("eu")
~>    session["prefs.region"] = region
    return "ok"
