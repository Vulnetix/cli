def tokenize(text, end):
    out = []
    pos = 0
~>    while pos < end:
        ch = text[pos]
        if ch.isspace():
            continue
        out.append(ch)
    return out
