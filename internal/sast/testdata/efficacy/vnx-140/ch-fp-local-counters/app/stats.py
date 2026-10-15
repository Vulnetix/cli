def dump(stats, path):
    count = len(stats)
    total = sum(stats)
    with open(path, "a") as fh:
        fh.write(f"{count},{total}\n")
        fh.write(",".join(str(s) for s in stats) + "\n")
