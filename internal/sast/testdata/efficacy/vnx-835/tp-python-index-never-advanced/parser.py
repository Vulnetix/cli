def read_fields(buf, n):
    fields = []
    i = 0
~>    while i < n:
        fields.append(buf[i])
        if buf[i] == 0:
            continue
    return fields


def skip_spaces(text, pos, end):
~>    while pos<end:
        ch = text[pos]
        handle(ch)
    return pos
