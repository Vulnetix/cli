from app.settings import DB_USER, DB_PASSWORD


def export_credentials():
    with open("/var/www/html/backup/credentials.txt", "w") as fh:
~>        fh.write(f"{DB_USER}:{DB_PASSWORD}\n")
