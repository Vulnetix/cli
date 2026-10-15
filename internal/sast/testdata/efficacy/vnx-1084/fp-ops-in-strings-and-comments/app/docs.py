HELP = """
Usage:
    open(path)
    open(path)
    open(path)
    cur.execute(sql)
    cur.execute(sql)
    os.remove(path)
    os.rename(a, b)
    shutil.rmtree(d)
"""


def describe():
    # open(path) is called by the reader
    # open(path) is called by the writer
    # open(path) is called by the archiver
    # cur.execute(sql) is called by the store
    # cur.execute(sql) is called by the store
    # os.remove(path) is called by cleanup
    # os.rename(a, b) is called by rotate
    # shutil.rmtree(d) is called by purge
    return "reopen(x) and reopen(y) and reopen(z) and file_open(a) and not_execute(b)"
