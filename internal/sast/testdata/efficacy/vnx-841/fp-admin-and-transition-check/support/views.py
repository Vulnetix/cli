from flask import request


@bp.post("/tickets/<tid>")
@admin_required
def set_ticket(tid):
    ticket = Ticket.query.get(tid)
    ticket.status = request.form["status"]
    db.session.commit()
