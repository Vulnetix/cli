from flask import request

from .extensions import db
from .models import Item


def update_item(item_id):
    item = @@sample:I[t]em[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(item_id)
~>    item.__dict__.update(request.json)
    db.session.commit()
    return "", 204


def update_item_vars(item_id):
    item = @@sample:I[t]em[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(item_id)
~>    vars(item).update(request.get_json())
    db.session.commit()
    return "", 204
