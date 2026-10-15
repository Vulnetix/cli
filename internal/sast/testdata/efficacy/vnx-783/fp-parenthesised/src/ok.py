def check(data, LIMIT):
    if (n := len(data)) > LIMIT:
        raise ValueError(n)
    while (chunk := read()) != b"":
        handle(chunk)
    value = (hi << 8) + lo
    return value
