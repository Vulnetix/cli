import hmac
import os

from flask import Flask, jsonify, request, session

app = Flask(__name__)
DEVICE_KEY = os.environ["DEVICE_KEY"].encode()


@app.post("/handshake/respond")
def respond():
    challenge = request.json["challenge"]
~>    answer = hmac.new(DEVICE_KEY, challenge.encode(), "sha256").hexdigest()
    return jsonify(answer=answer)


@app.post("/handshake/verify")
def verify():
    nonce = session.pop("nonce")
    want = hmac.new(DEVICE_KEY, nonce.encode(), "sha256").hexdigest()
    return jsonify(ok=hmac.compare_digest(want, request.json["answer"]))
