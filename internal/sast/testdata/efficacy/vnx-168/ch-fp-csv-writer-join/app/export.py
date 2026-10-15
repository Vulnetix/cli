def export_users(users, path="users.csv"):
    with open(path, "w") as out:
        out.write("name,email,role\n")
        for u in users:
            out.write(",".join(quote(f) for f in (u.name, u.email, u.role)) + "\n")


def quote(field):
    return '"' + field.replace('"', '""') + '"'
