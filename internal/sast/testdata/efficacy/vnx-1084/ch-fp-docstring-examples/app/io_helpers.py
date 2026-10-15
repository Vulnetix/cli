def copy_all(src, dst):
    """Copy every file.

    Equivalent to:

    >>> open("a").read()
    >>> open("b").read()
    >>> open("c").read()
    >>> open("d").read()
    >>> open("e").read()
    >>> open("f").read()
    >>> open("g").read()
    >>> open("h").read()
    """
    with open(src) as f:
        data = f.read()
    with open(dst, "w") as g:
        g.write(data)
