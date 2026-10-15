def show(request):
    note = request.session.get("cart_note")
    request.session.modified = True
    return note
