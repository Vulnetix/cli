from flask import request


def save_contact():
    out = open("contacts.csv", "a")
~>    out.write("{};{}\n".format(request.form["first"], request.form["last"]))
    out.close()
