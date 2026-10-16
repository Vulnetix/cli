def export_rows(rows, target):
    out = open(
        target,
        mode="w",
        encoding="utf-8",
    )
    for row in rows:
        out.write(",".join(row) + "\n")
    print("wrote", len(rows))
