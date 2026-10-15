import os


~>def sync_tree(
    src,
    dst,
    *,
    dry_run=False,
) -> int:
    with open(os.path.join(src, "index")) as f:
        names = f.read().split()
    for name in names:
        with open(os.path.join(src, name), "rb") as a, open(os.path.join(dst, name), "wb") as b:
            b.write(a.read())
    os.makedirs(os.path.join(dst, "meta"), exist_ok=True)
    with open(os.path.join(dst, "meta", "count"), "w") as f:
        f.write(str(len(names)))
    os.replace(os.path.join(dst, "index.tmp"), os.path.join(dst, "index"))
    os.remove(os.path.join(src, "lock"))
    os.rmdir(os.path.join(src, "tmp"))
    os.mkdir(os.path.join(src, "tmp"))
    return len(names)
