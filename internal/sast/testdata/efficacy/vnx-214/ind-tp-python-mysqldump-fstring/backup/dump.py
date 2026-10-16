import datetime
import subprocess


def dump_database(host, user, password, db, dest_dir):
    stamp = datetime.date.today().isoformat()
    out = f"{dest_dir}/{db}-{stamp}.sql"
    with open(out, "wb") as fh:
        subprocess.run(
~>            ["mysqldump", "-h", host, "-u", user, f"-p{password}", "--single-transaction", db],
            stdout=fh,
            check=True,
        )
    return out
