from flask import Flask, request, jsonify

app = Flask(__name__)

@app.post("/rules/test")
def test_rule():
    payload = request.get_json()
    condition = payload["condition"]
    result = eval(condition, {"__builtins__": {}}, {"order": load_order()})
    return jsonify(result=bool(result))
