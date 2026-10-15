def total(rows):
    data = load(rows)
    data = transform(data)
    count = len(data)
    count += 1
    name = rows[0].name
    name = name.strip()
    return data, count, name
