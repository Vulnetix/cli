from flask import request


def import_csv():
    f = request.files["report"]
    f.save("uploads/report.csv")
    return "", 201
