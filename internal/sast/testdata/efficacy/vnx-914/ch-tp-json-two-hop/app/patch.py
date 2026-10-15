from flask import request, abort


def patch_item(item):
    body = request.get_json(force=True)
    for name, val in body.items():
~>        setattr(item, name, val)
    db.session.commit()
