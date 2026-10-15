def find(rows, key):
    for row in rows:
        if row.key == key:
            break
    else:
        for row in rows:
            row.touch()
        return None
    return row
