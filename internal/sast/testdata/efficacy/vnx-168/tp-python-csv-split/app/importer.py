def import_users(db, path="uploads/users.csv"):
    with open(path) as f:
        next(f)
        for line in f:
~>            name, email, role = line.strip().split(",")
            db.add_user(name, email, role)


def import_rows(text):
    rows = []
    for raw in text.splitlines():
~>        rows.append(raw.split(','))
    return rows  # rows of the uploaded CSV
