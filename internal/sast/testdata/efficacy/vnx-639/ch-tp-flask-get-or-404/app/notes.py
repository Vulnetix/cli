from flask import request, jsonify


@app.route("/notes")
def note():
~>    n = @@sample:N[o]te[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(request.args.get("id"))
    return jsonify(n.to_dict())
