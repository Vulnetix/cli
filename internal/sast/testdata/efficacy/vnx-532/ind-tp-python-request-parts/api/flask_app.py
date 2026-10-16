from flask import Flask, current_app, jsonify, request

app = Flask(__name__)


@app.post("/api/payments")
def create_payment():
~>    current_app.logger.info("payment request %s", request.get_json())
~>    app.logger.debug(f"cookies: {request.cookies}")
    return jsonify(status="queued"), 202
