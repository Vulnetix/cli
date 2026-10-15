from flask import request


@bp.route("/account", methods=["PATCH"])
def update_account():
    data = request.get_json()
    account = @@sample:A[c]co[u]nt[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(g.user.id)
~>    account.update(**data)
    return "", 204
