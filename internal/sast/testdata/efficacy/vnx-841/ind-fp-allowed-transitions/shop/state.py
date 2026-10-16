from flask import request, abort

ALLOWED = {"draft": {"submitted"}, "submitted": {"cancelled"}}

def move(ticket):
    target = request.form["status"]
    if target not in ALLOWED.get(ticket.status, set()):
        abort(409)
    ticket.status = "submitted"
