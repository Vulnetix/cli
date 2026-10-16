def rotate(path):
    with open(path) as fh:
        data = fh.read()
    fh = open(path + ".1", "w")
    fh.write(data)
    fh.close()
    fh = open(path, "w")
    fh.write("")
    fh.close()
    if fh.closed:
        print("rotated")
