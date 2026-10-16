import datetime


def write_daily(path, rows):
    with open(path, "w") as f:
        f.write("date,count,total\n")
        for r in rows:
            stamp = datetime.date.today().isoformat()
            f.write(f"{stamp},{r.count},{r.total}\n")
