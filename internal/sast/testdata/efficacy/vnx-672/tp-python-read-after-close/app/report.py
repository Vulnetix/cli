def load_report(path):
    fh = open(path)
    header = fh.readline()
    fh.close()
~>    body = fh.read()
    return header, body


def save(path, rows):
    out = open(path, "w")
    out.close()
~>    out.write("\n".join(rows))
