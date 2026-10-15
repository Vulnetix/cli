from flask import Flask, jsonify, render_template

app = Flask(__name__)


@app.route("/signup", methods=["POST"])
def signup():
    try:
        create_account()
    except ValueError as e:
        return render_template("signup.html", error=str(e))
    except Exception:
        raise
    return jsonify({"ok": True})


@app.route("/health")
def health():
    try:
        db.ping()
    except Exception:
        return jsonify({"status": "degraded"})
    return jsonify({"status": "ok"})
