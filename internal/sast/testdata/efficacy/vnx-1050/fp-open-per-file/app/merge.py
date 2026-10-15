def merge(paths, out_path):
    with open(out_path, "w") as out:
        for path in paths:
            with open(path) as f:
                out.write(f.read())
    for line in open(out_path):
        print(line)
