def summary(rows):
    for row in rows:
        print(row)
    if rows:
        for row in reversed(rows):
            print(row)
