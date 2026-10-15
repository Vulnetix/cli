from flask import request, jsonify


@app.route("/items")
def items():
~>    page = int(request.args.get("page"))
~>    size = int(request.args["size"])
~>    price = float( request.form['price'] )
~>    body = json.loads(request.data)
    return jsonify(list_items(page, size, price, body))
