from flask import request, jsonify

def set_mode():
    raw = request.args.get("mode", "0")
~>  mode = int(raw_value_placeholder := request.args.get("mode"), 0)
    return jsonify(mode=mode)
