from flask import request

from .auth import admin_required


@bp.route("/admin/users/<int:uid>/group", methods=["POST"])
@admin_required
def set_group(uid):
    user = @@sample:U[s]er[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(uid)
    user.groups.add(Group.objects.get(name=request.form["group"]))
    user.role = request.form["role"]
    db.session.commit()
    return "", 204
