# email = request.json["email"].lower()  breaks on {"email": 5}
EXAMPLE = 'request.json["email"].lower()'
