from flask import request


def import_contacts():
    upload = request.files["contacts"]
    if not upload.filename.endswith(".csv"):
        return "bad file", 400
    contacts = []
    for line in upload.read().decode("utf-8").splitlines()[1:]:
~>        name, email, phone = line.split(",")
        contacts.append({"name": name, "email": email, "phone": phone})
    return contacts
