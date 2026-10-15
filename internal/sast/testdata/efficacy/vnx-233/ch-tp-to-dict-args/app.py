from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
~>    rows = Product.query.filter_by(**request.args.to_dict()).all()
    return {"n": len(rows)}
