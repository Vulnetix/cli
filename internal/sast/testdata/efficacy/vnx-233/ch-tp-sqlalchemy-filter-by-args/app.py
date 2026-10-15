from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/users")
def users():
~>    rows = db.session.query(User).filter_by(**request.args).all()
    return jsonify([r.to_dict() for r in rows])
