def count_lines(path):
    f = open(path)
    try:
        return sum(1 for _ in f)
    finally:
        f.close()
