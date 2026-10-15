def parse(text):
    try:
        v = int(text)
    except ValueError:
        v = float(text)
    if (n := len(text)) > 3:
        n = 3
    return v, n
