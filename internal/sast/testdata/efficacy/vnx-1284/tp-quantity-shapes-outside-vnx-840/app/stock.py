from flask import Flask, request

app = Flask(__name__)


@app.route("/restock", methods=["POST"])
def restock():
    product = Product.query.get(request.form["sku"])
~>    product.stock += int(request.form["quantity"])
~>    product.reserved -= int(request.form['units'])
    db.session.commit()
    return {"ok": True}
